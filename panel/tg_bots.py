"""Telegram-bot runner + anti-fraud notifier for xnPanel.

The panel runs one aiogram Dispatcher per configured TgBot in-process, as
asyncio tasks started on FastAPI startup. A single background loop owns
the lifecycle: it periodically reconciles TgBot rows in the DB against a
set of running tasks, starting new ones and stopping tasks whose row
disappeared or got disabled.

Anti-fraud: another loop walks recent ``device_fingerprints`` per
bot-user and, whenever the distinct-UA count in the last 24h crosses a
bot's ``device_limit``, pings ``owner_chat_id`` with a ban/ignore inline
keyboard. Callback handlers apply the ban (flipping Client.enabled and
TgBotUser.banned, re-pushing xray config) or mark the alert acknowledged.
"""
from __future__ import annotations

import asyncio
import hashlib
import logging
import os
import secrets as _secrets
from datetime import datetime, timedelta
from typing import Optional

from aiogram import Bot, Dispatcher, F, Router, types
from aiogram.client.default import DefaultBotProperties
from aiogram.exceptions import TelegramAPIError, TelegramUnauthorizedError
from aiogram.filters import Command, CommandStart
from aiogram.types import (
    CallbackQuery,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    Message,
    ReplyKeyboardMarkup,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit as audit_mod
from .agent_client import AgentClient, AgentError
from .database import SessionLocal
from .models import (
    AuditLog,
    Client,
    DeviceFingerprint,
    Server,
    TgBot,
    TgBotUser,
)
from .xray_config import build_config, build_vless_link


log = logging.getLogger("xnpanel.tg_bots")


# ---------- helpers ----------
def fingerprint_of(user_agent: str, ip: str) -> str:
    """Stable hash for (UA, IP). Keeps raw values separately for UI."""
    h = hashlib.sha256()
    h.update((user_agent or "").strip().encode("utf-8", errors="replace"))
    h.update(b"|")
    h.update((ip or "").strip().encode("utf-8", errors="replace"))
    return h.hexdigest()[:32]


def record_fingerprint(
    db: Session, *, sub_token: str, user_agent: str, ip: str
) -> None:
    """Called from the subscription endpoint on every successful fetch."""
    if not sub_token:
        return
    fp = fingerprint_of(user_agent, ip)
    # Keep one row per (sub_token, fingerprint) within a 24h window to keep
    # the table small. We don't UPSERT because SQLite's syntax is painful —
    # instead we insert freely and let the periodic sweep dedupe+trim.
    db.add(DeviceFingerprint(
        sub_token=sub_token,
        fingerprint=fp,
        user_agent=(user_agent or "")[:255],
        ip=(ip or "")[:64],
    ))
    db.commit()


def _push_config_for_server(db: Session, server: Server) -> None:
    """Re-build and push xray config to the agent for ``server``.

    Collects every active client on the server so the push is always
    complete — individual adds/removes never desync from xray.
    """
    active = [
        {"id": c.uuid, "email": c.email, "flow": c.flow}
        for c in server.clients
        if c.is_active()
    ]
    try:
        AgentClient(server.agent_url, server.agent_token).put_config(
            build_config(
                port=server.port,
                sni=server.sni,
                dest=server.dest,
                private_key=server.private_key,
                short_ids=[server.short_id],
                clients=active,
            )
        )
    except AgentError as exc:
        log.warning("xray config push failed for server=%d: %s", server.id, exc)
    except Exception as exc:  # pragma: no cover — transport / DNS / timeouts
        log.warning("xray config push crashed for server=%d: %s", server.id, exc)


def _push_server_config_for_client(db: Session, client: Client) -> None:
    """Compat shim — push the config for ``client``'s server."""
    server = db.get(Server, client.server_id)
    if server is not None:
        _push_config_for_server(db, server)


def pick_default_server(db: Session, bot_row: TgBot) -> Optional[Server]:
    if bot_row.default_server_id:
        s = db.get(Server, bot_row.default_server_id)
        if s is not None:
            return s
    # Fallback: lowest-ID server.
    return db.scalars(select(Server).order_by(Server.id)).first()


def _target_servers(db: Session, bot_row: TgBot) -> list[Server]:
    """Which servers should this bot hand out keys for?

    Explicit ``bot_row.servers`` wins. When empty, fall back to
    ``default_server_id``, then to the lowest-ID server. Returns an empty
    list when the panel has no servers at all.
    """
    if bot_row.servers:
        return list(bot_row.servers)
    s = pick_default_server(db, bot_row)
    return [s] if s is not None else []


def _ensure_bot_user_clients(
    db: Session, bot_row: TgBot, bu: TgBotUser
) -> list[Client]:
    """Reconcile ``bu``'s clients to match the bot's configured servers.

    For every server in ``_target_servers(bot_row)`` that doesn't already
    have a client for this user, create one with the bot's defaults and
    link it via the ``tg_bot_user_clients`` junction. Then push the xray
    config for every server whose client set actually changed.

    Returns the list of currently-issued on-target clients. Safe to call
    repeatedly — idempotent.
    """
    import uuid as _uuid

    target = _target_servers(db, bot_row)
    if not target:
        return []
    target_by_id: dict[int, Server] = {s.id: s for s in target}

    # Index existing clients by server_id, folding the legacy pointer.
    existing: dict[int, Client] = {}
    for c in list(bu.clients):
        existing.setdefault(c.server_id, c)
    if bu.client_id:
        legacy = db.get(Client, bu.client_id)
        if legacy is not None:
            existing.setdefault(legacy.server_id, legacy)
            if legacy not in bu.clients:
                bu.clients.append(legacy)

    expires_at = None
    if bot_row.default_days and bot_row.default_days > 0:
        expires_at = datetime.utcnow() + timedelta(days=bot_row.default_days)
    data_limit = bot_row.default_data_limit_bytes or None

    dirty_servers: set[int] = set()
    for sid, server in target_by_id.items():
        if sid in existing:
            continue
        c = Client(
            server_id=sid,
            uuid=str(_uuid.uuid4()),
            email=f"tg-{bot_row.id}-{bu.tg_user_id}-{sid}",
            label=f"tg:{bot_row.name}",
            flow="xtls-rprx-vision",
            data_limit_bytes=data_limit,
            expires_at=expires_at,
            enabled=True,
        )
        db.add(c)
        db.flush()
        bu.clients.append(c)
        if bu.client_id is None:
            bu.client_id = c.id
        existing[sid] = c
        dirty_servers.add(sid)

    if dirty_servers:
        db.commit()
        # Reload servers cleanly before rebuilding each config.
        for sid in dirty_servers:
            server = db.get(Server, sid)
            if server is not None:
                _push_config_for_server(db, server)

    return [existing[sid] for sid in target_by_id if sid in existing]


# ---------- per-bot handlers ----------
def _build_router(bot_id: int) -> Router:
    """Return a Router whose handlers close over ``bot_id``.

    The router is recreated when the bot row is recreated, but it captures
    only the DB row id — every handler opens its own session so state is
    always fresh.
    """

    router = Router(name=f"bot-{bot_id}")

    # ------------------------------------------------------------------ /start
    @router.message(CommandStart())
    async def on_start(msg: Message) -> None:  # pragma: no cover — I/O
        with SessionLocal() as db:
            bot_row = db.get(TgBot, bot_id)
            if bot_row is None or not bot_row.enabled:
                await msg.answer("Бот отключён администратором.")
                return

            u = msg.from_user
            if u is None:
                return

            # Upsert the bot user.
            bu = db.scalar(
                select(TgBotUser).where(
                    TgBotUser.bot_id == bot_id,
                    TgBotUser.tg_user_id == str(u.id),
                )
            )
            if bu is None:
                bu = TgBotUser(
                    bot_id=bot_id,
                    tg_user_id=str(u.id),
                    tg_username=(u.username or "")[:64],
                    first_name=(u.first_name or "")[:64],
                    sub_token=_secrets.token_urlsafe(24),
                )
                db.add(bu)
                db.flush()

            # If banned, answer and stop.
            if bu.banned:
                await msg.answer(
                    "Доступ заблокирован администратором за превышение лимита устройств."
                )
                return

            # Ensure the user has a client on every configured server
            # and the xray config on each is up to date. Idempotent.
            issued = _ensure_bot_user_clients(db, bot_row, bu)
            if not issued:
                await msg.answer(
                    "Пока нет доступных серверов — попробуй позже."
                )
                db.commit()
                return

            audit_mod.record(
                db,
                user=None,
                action="bot.start",
                resource_type="tg_bot_user",
                resource_id=bu.id,
                details=(
                    f"tg-bot={bot_row.name} tg_user=@{u.username or u.id} "
                    f"servers={','.join(str(c.server_id) for c in issued)}"
                ),
            )
            db.commit()

            welcome = bot_row.welcome_text.strip() or (
                "👋 <b>Привет!</b>\n\n"
                "Это VPN на основе VLESS + Reality — быстро, без блокировок, "
                "без лишних настроек.\n\n"
                "Жми «💳 Моя подписка» чтобы получить свою ссылку, или "
                "«📖 Инструкция по подключению» — расскажу как настроить "
                "клиент под твою платформу."
            )
            await msg.answer(
                welcome,
                reply_markup=_main_keyboard(),
                disable_web_page_preview=True,
            )

    # -------------------------------------------------------------- /mysub
    async def _send_mysub(msg: Message) -> None:
        with SessionLocal() as db:
            bu = _current_bot_user(db, bot_id, msg)
            if bu is None:
                await msg.answer(
                    "Сначала отправь /start.", reply_markup=_main_keyboard()
                )
                return
            if bu.banned:
                await msg.answer("Доступ заблокирован администратором.")
                return
            bot_row = db.get(TgBot, bot_id)
            # Reconcile every time the user taps — picks up new servers,
            # re-pushes xray config if it drifted for any reason.
            clients: list[Client] = []
            if bot_row is not None:
                clients = _ensure_bot_user_clients(db, bot_row, bu)
            sub_url = _subscription_base_url(db) + f"/sub/{bu.sub_token}"
            await msg.answer(
                _format_mysub(bu, clients, sub_url),
                reply_markup=_main_keyboard(),
                disable_web_page_preview=True,
            )

    @router.message(Command("mysub"))
    async def on_mysub(msg: Message) -> None:  # pragma: no cover
        await _send_mysub(msg)

    @router.message(F.text == _MAIN_KB_BUTTONS["sub"])
    async def on_btn_mysub(msg: Message) -> None:  # pragma: no cover
        await _send_mysub(msg)

    # ----------------------------------------- reply buttons (buy / partner / about)
    @router.message(F.text == _MAIN_KB_BUTTONS["buy"])
    async def on_btn_buy(msg: Message) -> None:  # pragma: no cover
        await msg.answer(_BUY_TEXT, reply_markup=_main_keyboard())

    @router.message(F.text == _MAIN_KB_BUTTONS["partner"])
    async def on_btn_partner(msg: Message) -> None:  # pragma: no cover
        await msg.answer(_PARTNER_TEXT, reply_markup=_main_keyboard())

    @router.message(F.text == _MAIN_KB_BUTTONS["about"])
    async def on_btn_about(msg: Message) -> None:  # pragma: no cover
        await msg.answer(
            _ABOUT_TEXT, reply_markup=_main_keyboard(), disable_web_page_preview=True
        )

    @router.message(F.text == _MAIN_KB_BUTTONS["help"])
    async def on_btn_help(msg: Message) -> None:  # pragma: no cover
        await msg.answer(
            "📖 <b>Выбери платформу</b> — пришлю пошаговую инструкцию:",
            reply_markup=_instructions_keyboard(),
        )

    @router.callback_query(F.data.startswith("sub:help:"))
    async def on_cb_help(cb: CallbackQuery) -> None:  # pragma: no cover
        platform = (cb.data or "").split(":", 2)[-1]
        text = _INSTRUCTIONS.get(platform)
        if text is None:
            await cb.answer()
            return
        await cb.answer()
        if cb.message is not None:
            try:
                await cb.message.answer(
                    text,
                    reply_markup=_instructions_keyboard(),
                    disable_web_page_preview=True,
                )
            except TelegramAPIError:
                pass

    # ------------------------------------------------------------ /formats
    @router.message(Command("formats"))
    async def on_formats(msg: Message) -> None:  # pragma: no cover
        with SessionLocal() as db:
            bu = _current_bot_user(db, bot_id, msg)
            if bu is None:
                await msg.answer("Сначала отправь /start.")
                return
            if bu.banned:
                await msg.answer("Доступ заблокирована администратором.")
                return
            base = _subscription_base_url(db) + f"/sub/{bu.sub_token}"
            lines = [
                "Форматы подписки:",
                f"• base64: <code>{base}</code>",
                f"• clash:  <code>{base}?format=clash</code>",
                f"• singbox: <code>{base}?format=singbox</code>",
                f"• vless plain: <code>{base}?format=vless</code>",
            ]
            await msg.answer("\n".join(lines), disable_web_page_preview=True)

    # ----------------------------------------------------- /instructions
    @router.message(Command("instructions"))
    async def on_instructions(msg: Message) -> None:  # pragma: no cover
        await msg.answer(
            "📖 <b>Выбери платформу</b> — пришлю пошаговую инструкцию:",
            reply_markup=_instructions_keyboard(),
        )

    # ---------------- admin: /ban <tg_user_id>, /unban <tg_user_id>
    @router.message(Command("ban"))
    async def on_ban(msg: Message) -> None:  # pragma: no cover
        with SessionLocal() as db:
            bot_row = db.get(TgBot, bot_id)
            if bot_row is None:
                return
            if str(msg.from_user.id) != str(bot_row.owner_chat_id):
                await msg.answer("Команда доступна только владельцу бота.")
                return
            parts = (msg.text or "").split()
            if len(parts) < 2:
                await msg.answer("Использование: /ban <tg_user_id>")
                return
            target = parts[1].strip()
            bu = db.scalar(select(TgBotUser).where(
                TgBotUser.bot_id == bot_id,
                TgBotUser.tg_user_id == target,
            ))
            if bu is None:
                await msg.answer(f"Пользователь {target} не найден.")
                return
            _apply_ban(db, bu, banned=True)
            db.commit()
            await msg.answer(f"Пользователь {target} заблокирован.")

    @router.message(Command("unban"))
    async def on_unban(msg: Message) -> None:  # pragma: no cover
        with SessionLocal() as db:
            bot_row = db.get(TgBot, bot_id)
            if bot_row is None:
                return
            if str(msg.from_user.id) != str(bot_row.owner_chat_id):
                await msg.answer("Команда доступна только владельцу бота.")
                return
            parts = (msg.text or "").split()
            if len(parts) < 2:
                await msg.answer("Использование: /unban <tg_user_id>")
                return
            target = parts[1].strip()
            bu = db.scalar(select(TgBotUser).where(
                TgBotUser.bot_id == bot_id,
                TgBotUser.tg_user_id == target,
            ))
            if bu is None:
                await msg.answer(f"Пользователь {target} не найден.")
                return
            _apply_ban(db, bu, banned=False)
            db.commit()
            await msg.answer(f"Пользователь {target} разблокирован.")

    # ---------------- anti-fraud inline buttons
    @router.callback_query(F.data.startswith("bot:ban:"))
    async def on_cb_ban(cb: CallbackQuery) -> None:  # pragma: no cover
        with SessionLocal() as db:
            bot_row = db.get(TgBot, bot_id)
            if bot_row is None:
                await cb.answer()
                return
            if str(cb.from_user.id) != str(bot_row.owner_chat_id):
                await cb.answer("Только владелец бота может банить.",
                                show_alert=True)
                return
            try:
                bu_id = int((cb.data or "").split(":", 2)[2])
            except (ValueError, IndexError):
                await cb.answer()
                return
            bu = db.get(TgBotUser, bu_id)
            if bu is None:
                await cb.answer("Пользователь уже удалён.")
                return
            _apply_ban(db, bu, banned=True)
            db.commit()
            await cb.answer("Заблокирован.")
            try:
                if cb.message is not None:
                    await cb.message.edit_text(
                        (cb.message.text or "") + "\n\n<b>✖ Заблокирован.</b>"
                    )
            except TelegramAPIError:
                pass

    @router.callback_query(F.data.startswith("bot:ignore:"))
    async def on_cb_ignore(cb: CallbackQuery) -> None:  # pragma: no cover
        await cb.answer("Проигнорировано.")
        try:
            if cb.message is not None:
                await cb.message.edit_text(
                    (cb.message.text or "") + "\n\n<b>✓ Оставлено без изменений.</b>"
                )
        except TelegramAPIError:
            pass

    return router


def _current_bot_user(db: Session, bot_id: int, msg: Message) -> Optional[TgBotUser]:
    if msg.from_user is None:
        return None
    return db.scalar(select(TgBotUser).where(
        TgBotUser.bot_id == bot_id,
        TgBotUser.tg_user_id == str(msg.from_user.id),
    ))


def _apply_ban(db: Session, bu: TgBotUser, *, banned: bool) -> None:
    """Flip the bot user's banned state and mirror it to Client.enabled."""
    bu.banned = banned
    if bu.client_id:
        client = db.get(Client, bu.client_id)
        if client is not None:
            client.enabled = not banned
            db.flush()
            try:
                _push_server_config_for_client(db, client)
            except Exception as exc:
                log.warning("config push on ban failed: %s", exc)
    audit_mod.record(
        db,
        user=None,
        action="bot.user_ban" if banned else "bot.user_unban",
        resource_type="tg_bot_user",
        resource_id=bu.id,
        details=f"bot_id={bu.bot_id} tg_user={bu.tg_user_id}",
    )


def _subscription_base_url(db: Session) -> str:
    """Resolve the public URL prefix for subscription links.

    Lookup order:
      1. Settings row ``panel.public_url`` (admin set via UI).
      2. ``PANEL_PUBLIC_URL`` env var (installer sets it from
         ``PANEL_DOMAIN`` + ``CADDY_PORT``).
      3. ``http://localhost:8443`` as the last-resort local fallback
         so at least ``/mysub`` returns *something* before the admin
         has configured the panel.
    """
    url = audit_mod.setting_get(db, "panel.public_url", "").strip()
    if not url:
        url = os.environ.get("PANEL_PUBLIC_URL", "").strip()
    return url.rstrip("/") or "http://localhost:8443"


# Per-platform connection instructions, adapted from the production
# xankaVPN bot. Uses HTML so Telegram renders emoji + bold nicely.
_INSTRUCTIONS: dict[str, str] = {
    "windows": (
        "💻 <b>Windows (Happ)</b>\n\n"
        "1. Скачай и установи Happ:\n"
        "https://github.com/Happ-proxy/happ-desktop/releases/latest/download/setup-Happ.x64.exe\n\n"
        "2. Открой ссылку подписки, которую прислал бот.\n"
        "3. На странице нажми кнопку «Happ». Если приложение установлено — "
        "подписка добавится автоматически.\n\n"
        "4. Если кнопка не сработала:\n"
        "   • пролистай страницу вниз\n"
        "   • нажми «Скопировать ссылку»\n"
        "   • открой Happ → «+» → «Добавить из буфера обмена»\n\n"
        "5. Чтобы авто-выбирать лучший сервер:\n"
        "   • Настройки (шестерёнка) → «Подписки»\n"
        "   • Включи «Сортировать по пингу» и «Пинг при открытии»"
    ),
    "android": (
        "🤖 <b>Android (Happ)</b>\n\n"
        "1. Установи Happ из Google Play:\n"
        "https://play.google.com/store/apps/details?id=com.happproxy\n\n"
        "2. Открой ссылку подписки, которую прислал бот.\n"
        "3. На странице нажми «Happ» — подписка добавится автоматически.\n\n"
        "4. Если не сработало:\n"
        "   • пролистай страницу вниз → «Скопировать ссылку»\n"
        "   • в Happ: «+» → «Добавить из буфера обмена»\n\n"
        "5. В «Настройки → Подписки» включи «Сортировать по пингу» + "
        "«Пинг при открытии»."
    ),
    "iphone": (
        "🍎 <b>iPhone (Happ)</b>\n\n"
        "1. Установи Happ из App Store:\n"
        "https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973\n\n"
        "2. Открой ссылку подписки, которую прислал бот.\n"
        "3. Нажми «Happ» на странице подписки — подписка подцепится "
        "автоматически.\n\n"
        "4. Если не получилось:\n"
        "   • пролистай вниз → «Скопировать ссылку»\n"
        "   • Happ → «+» → «Добавить из буфера»\n\n"
        "5. «Настройки → Подписки» → «Сортировать по пингу» + "
        "«Пинг при запуске»."
    ),
    "macos": (
        "💻 <b>macOS (Happ)</b>\n\n"
        "1. Установи Happ из App Store:\n"
        "https://apps.apple.com/ru/app/happ-proxy-utility-plus/id6746188973\n\n"
        "2. Открой ссылку подписки из бота.\n"
        "3. Нажми «Happ» на странице — подцепится автоматически.\n\n"
        "4. Иначе: «Скопировать ссылку» → Happ → «+» → «Добавить из буфера».\n\n"
        "5. В настройках включи «Сортировать по пингу» + «Пинг при запуске»."
    ),
    "androidtv": (
        "📺 <b>Android TV (Happ)</b>\n\n"
        "1. Установи Happ для TV из Google Play.\n"
        "2. Открой ссылку подписки на телефоне → «Скопировать ссылку».\n"
        "3. В Happ на TV выбери «Ручной ввод» и вставь ссылку.\n\n"
        "4. В настройках включи «Сортировать по пингу» и «Пинг при открытии» — "
        "TV-клиент будет автоматически подбирать ближайший сервер."
    ),
}

_MAIN_KB_BUTTONS = {
    "sub": "💳 Моя подписка",
    "buy": "🛒 Купить подписку",
    "partner": "🤝 Партнёрская программа",
    "help": "📖 Инструкция по подключению",
    "about": "ℹ️ О сервисе",
}


def _main_keyboard() -> ReplyKeyboardMarkup:
    """Reply keyboard mirroring the xankaVPN bot layout (2 columns)."""
    rows = [
        [KeyboardButton(text=_MAIN_KB_BUTTONS["sub"]),
         KeyboardButton(text=_MAIN_KB_BUTTONS["buy"])],
        [KeyboardButton(text=_MAIN_KB_BUTTONS["partner"]),
         KeyboardButton(text=_MAIN_KB_BUTTONS["help"])],
        [KeyboardButton(text=_MAIN_KB_BUTTONS["about"])],
    ]
    return ReplyKeyboardMarkup(keyboard=rows, resize_keyboard=True)


def _instructions_keyboard() -> InlineKeyboardMarkup:
    buttons = [
        [InlineKeyboardButton(text="💻 Windows", callback_data="sub:help:windows"),
         InlineKeyboardButton(text="🍎 iPhone",  callback_data="sub:help:iphone")],
        [InlineKeyboardButton(text="🤖 Android", callback_data="sub:help:android"),
         InlineKeyboardButton(text="💻 macOS",   callback_data="sub:help:macos")],
        [InlineKeyboardButton(text="📺 Android TV", callback_data="sub:help:androidtv")],
    ]
    return InlineKeyboardMarkup(inline_keyboard=buttons)


def _format_mysub(
    bu: "TgBotUser", clients: "list[Client]", sub_url: str
) -> str:
    """Format the «Моя подписка» card.

    Shows the single subscription URL (clients auto-pull all servers
    from it) plus a summary of the issued keys — server name(s),
    expiry, and traffic cap.
    """
    lines = [
        "💳 <b>Твоя подписка</b>",
        "",
        "<b>Ссылка для клиента:</b>",
        f"<code>{sub_url}</code>",
    ]
    if clients:
        names = sorted({(c.server.name if c.server is not None else "?") for c in clients})
        if len(names) == 1:
            lines.append(f"\n🌍 Сервер: <b>{names[0]}</b>")
        else:
            lines.append(
                f"\n🌍 Серверы ({len(names)}): <b>{', '.join(names)}</b>"
            )
        # Expiry/limit are set from the bot's defaults, so they match
        # across all issued clients — just show the first one.
        ref = clients[0]
        if ref.expires_at:
            lines.append(
                f"📅 Действует до: <b>{ref.expires_at.strftime('%d.%m.%Y %H:%M')}</b> UTC"
            )
        else:
            lines.append("♾ Срок действия: <b>без ограничений</b>")
        if ref.data_limit_bytes:
            gb = ref.data_limit_bytes / (1024 ** 3)
            lines.append(f"📊 Лимит трафика: <b>{gb:.1f} ГБ</b>")
    lines.extend([
        "",
        "Скопируй ссылку и вставь в клиент (Happ / v2rayNG / sing-box). "
        "Подробная инструкция — в разделе «Инструкция по подключению».",
    ])
    return "\n".join(lines)


_ABOUT_TEXT = (
    "ℹ️ <b>О сервисе</b>\n\n"
    "Это VPN на базе протокола VLESS + Reality — один из самых устойчивых "
    "способов обхода блокировок в 2025 году. Трафик маскируется под обычный "
    "HTTPS на доверенный домен, поэтому провайдер не может его отличить от "
    "стандартного веб-браузинга.\n\n"
    "• Без рекламы и логирования\n"
    "• Мгновенное подключение по ссылке подписки\n"
    "• Работает на Windows, macOS, iOS, Android, Android TV, Linux\n\n"
    "По вопросам — пиши администратору."
)

_BUY_TEXT = (
    "🛒 <b>Купить подписку</b>\n\n"
    "В этом боте пока доступен бесплатный пробный доступ, выдаваемый "
    "администратором при команде /start.\n\n"
    "Оплата через Stars / CryptoBot / карту появится в ближайшем обновлении."
)

_PARTNER_TEXT = (
    "🤝 <b>Партнёрская программа</b>\n\n"
    "Скоро: зарабатывай процент с оплат по твоей реферальной ссылке."
)


# ---------- lifecycle ----------
class BotRunner:
    """One polling task + Bot + Dispatcher per DB row."""

    def __init__(self, bot_id: int, bot_token: str) -> None:
        self.bot_id = bot_id
        self.bot_token = bot_token
        self.task: Optional[asyncio.Task] = None
        self.bot: Optional[Bot] = None
        self.dp: Optional[Dispatcher] = None
        self.failed: bool = False

    async def start(self) -> None:
        self.bot = Bot(
            token=self.bot_token,
            default=DefaultBotProperties(parse_mode="HTML"),
        )
        self.dp = Dispatcher()
        self.dp.include_router(_build_router(self.bot_id))
        self.task = asyncio.create_task(self._run(), name=f"tg-bot-{self.bot_id}")

    async def _run(self) -> None:
        assert self.bot is not None and self.dp is not None
        try:
            await self.dp.start_polling(self.bot, handle_signals=False)
        except (TelegramUnauthorizedError, TelegramAPIError) as exc:
            log.error("bot %s stopped: %s", self.bot_id, exc)
            self.failed = True
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pragma: no cover
            log.exception("bot %s crashed: %s", self.bot_id, exc)
            self.failed = True
        finally:
            try:
                if self.bot is not None:
                    await self.bot.session.close()
            except Exception:
                pass

    async def stop(self) -> None:
        if self.dp is not None:
            try:
                await self.dp.stop_polling()
            except Exception:  # pragma: no cover
                pass
        if self.task is not None and not self.task.done():
            self.task.cancel()
            try:
                await self.task
            except (asyncio.CancelledError, Exception):
                pass
        try:
            if self.bot is not None:
                await self.bot.session.close()
        except Exception:  # pragma: no cover
            pass


class BotManager:
    """Owns the set of running BotRunners and keeps it in sync with the DB.

    Also owns the anti-fraud loop which periodically scans fingerprints
    and alerts bot owners.
    """

    def __init__(self) -> None:
        self.runners: dict[int, BotRunner] = {}
        self._reconcile_task: Optional[asyncio.Task] = None
        self._fraud_task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        self._reconcile_task = asyncio.create_task(
            self._reconcile_loop(), name="tg-bot-reconciler"
        )
        self._fraud_task = asyncio.create_task(
            self._fraud_loop(), name="tg-bot-fraud-scan"
        )

    async def stop(self) -> None:
        self._stopping.set()
        for t in (self._reconcile_task, self._fraud_task):
            if t is not None and not t.done():
                t.cancel()
                try:
                    await t
                except (asyncio.CancelledError, Exception):
                    pass
        for runner in list(self.runners.values()):
            await runner.stop()
        self.runners.clear()

    async def _reconcile_loop(self) -> None:
        """Every 5s: start enabled bots that aren't running, stop others."""
        while not self._stopping.is_set():
            try:
                await self._reconcile_once()
            except Exception as exc:  # pragma: no cover
                log.warning("bot reconcile failed: %s", exc)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                pass

    async def _reconcile_once(self) -> None:
        with SessionLocal() as db:
            rows: list[TgBot] = list(db.scalars(select(TgBot)).all())
        want: dict[int, str] = {r.id: r.bot_token for r in rows if r.enabled}

        # Stop removed / disabled / retoken'd runners.
        for bid in list(self.runners.keys()):
            runner = self.runners[bid]
            target = want.get(bid)
            if target is None or target != runner.bot_token or runner.failed:
                await runner.stop()
                del self.runners[bid]

        # Start missing.
        for bid, token in want.items():
            if bid in self.runners:
                continue
            runner = BotRunner(bid, token)
            try:
                await runner.start()
            except Exception as exc:
                log.warning("bot %s start failed: %s", bid, exc)
                continue
            self.runners[bid] = runner

    async def _fraud_loop(self) -> None:
        """Every 60s: scan fingerprints, alert over-limit bot users."""
        while not self._stopping.is_set():
            try:
                await self._fraud_scan()
            except Exception as exc:  # pragma: no cover
                log.warning("fraud scan failed: %s", exc)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60.0)
            except asyncio.TimeoutError:
                pass

    async def _fraud_scan(self) -> None:
        # Find (sub_token, distinct fingerprints in last 24h) for every
        # bot user and compare to that bot's device_limit.
        horizon = datetime.utcnow() - timedelta(hours=24)
        with SessionLocal() as db:
            rows = list(db.execute(
                select(
                    TgBotUser.id,
                    TgBotUser.bot_id,
                    TgBotUser.tg_user_id,
                    TgBotUser.tg_username,
                    TgBotUser.last_alert_at,
                    TgBotUser.sub_token,
                )
            ).all())
            # Group counts.
            counts_rows = list(db.execute(
                select(
                    DeviceFingerprint.sub_token,
                    func.count(func.distinct(DeviceFingerprint.fingerprint)),
                ).where(DeviceFingerprint.created_at >= horizon)
                 .group_by(DeviceFingerprint.sub_token)
            ).all())
            counts = {token: n for token, n in counts_rows}

            alerts: list[tuple[TgBot, TgBotUser, int]] = []
            for row in rows:
                bu_id, bot_id, tg_uid, tg_uname, last_alert, tok = row
                n = counts.get(tok, 0)
                bot_row = db.get(TgBot, bot_id)
                if bot_row is None or not bot_row.owner_chat_id:
                    continue
                if bot_row.device_limit <= 0:
                    continue
                if n <= bot_row.device_limit:
                    continue
                # Throttle to one alert per 3 hours per user.
                if last_alert is not None and datetime.utcnow() - last_alert < timedelta(hours=3):
                    continue
                bu = db.get(TgBotUser, bu_id)
                if bu is None or bu.banned:
                    continue
                alerts.append((bot_row, bu, n))
                bu.last_alert_at = datetime.utcnow()
            db.commit()

        # Send after closing the DB session.
        for bot_row, bu, n in alerts:
            runner = self.runners.get(bot_row.id)
            if runner is None or runner.bot is None:
                continue
            try:
                who = f"@{bu.tg_username}" if bu.tg_username else f"id={bu.tg_user_id}"
                text = (
                    f"⚠ <b>Подозрение на фрод</b>\n"
                    f"Пользователь {who} — {n} устройств за 24ч "
                    f"(лимит {bot_row.device_limit}).\n"
                    f"Ключ: <code>tg-{bot_row.id}-{bu.tg_user_id}</code>"
                )
                kb = InlineKeyboardMarkup(inline_keyboard=[[
                    InlineKeyboardButton(
                        text="🚫 Забанить", callback_data=f"bot:ban:{bu.id}"
                    ),
                    InlineKeyboardButton(
                        text="🙈 Игнорировать", callback_data=f"bot:ignore:{bu.id}"
                    ),
                ]])
                await runner.bot.send_message(
                    chat_id=bot_row.owner_chat_id,
                    text=text,
                    reply_markup=kb,
                )
            except TelegramAPIError as exc:
                log.warning("fraud alert send failed: %s", exc)

    async def prune_fingerprints(self, horizon_hours: int = 48) -> None:
        """Drop fingerprints older than N hours — called from reconcile."""
        horizon = datetime.utcnow() - timedelta(hours=horizon_hours)
        with SessionLocal() as db:
            db.execute(
                DeviceFingerprint.__table__.delete().where(
                    DeviceFingerprint.created_at < horizon
                )
            )
            db.commit()


# Module-level singleton accessed from app.py startup/shutdown hooks.
manager = BotManager()

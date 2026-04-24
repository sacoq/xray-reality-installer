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
    ErrorEvent,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    KeyboardButton,
    LabeledPrice,
    Message,
    PreCheckoutQuery,
    ReplyKeyboardMarkup,
)
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit as audit_mod
from . import payments as payments_mod
from .agent_client import AgentError
from .database import SessionLocal
from .models import (
    AuditLog,
    Client,
    DeviceFingerprint,
    Order,
    Plan,
    Server,
    TgBot,
    TgBotUser,
)
from .xray_config import build_vless_link
from .xray_push import push_config as _mode_aware_push_config


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

    Delegates to the shared ``xray_push.push_config`` helper so the
    correct branch (standalone vs balancer) is applied automatically:
    a balancer server gets its pool-aware config with observatory +
    leastPing routing; a standalone server gets a plain Reality
    inbound. Failures are logged but swallowed — the bot runs in a
    worker thread and should never crash a user flow because an agent
    is temporarily unreachable.
    """
    try:
        _mode_aware_push_config(server, db)
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
        # Email is deterministic (tg-<bot>-<tg_user>-<server>), and the
        # clients table has UNIQUE(server_id, email). A previous /start
        # attempt may have committed a Client row with this exact email
        # while the TgBotUser / junction insert was rolled back — that
        # left an orphaned Client in the DB, and every subsequent /start
        # blew up with an IntegrityError on the blind INSERT below,
        # which (without a handler-level try/except) meant aiogram
        # silently dropped the /start reply. Adopt the orphan instead.
        email = f"tg-{bot_row.id}-{bu.tg_user_id}-{sid}"
        c = db.scalar(
            select(Client).where(
                Client.server_id == sid, Client.email == email
            )
        )
        created = False
        if c is None:
            c = Client(
                server_id=sid,
                uuid=str(_uuid.uuid4()),
                email=email,
                label=f"tg:{bot_row.name}",
                flow="xtls-rprx-vision",
                data_limit_bytes=data_limit,
                expires_at=expires_at,
                enabled=True,
            )
            db.add(c)
            db.flush()
            created = True
        if c not in bu.clients:
            bu.clients.append(c)
        if bu.client_id is None:
            bu.client_id = c.id
        existing[sid] = c
        # Reconciliation touched xray for this server if we created a
        # fresh client. Adopting an orphan doesn't change the key set
        # pushed to xray, so no need to republish.
        if created:
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
            is_new = bu is None
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
                # Persist the bot user row immediately. Without this, if
                # _ensure_bot_user_clients() or the agent push raises,
                # the whole transaction gets rolled back and the user
                # "disappears" — which was the exact «/start ничего не
                # отвечает» symptom reported by users: retrying /start
                # keeps re-inserting a fresh row that gets rolled back
                # again, the panel's user count stays at 0, and aiogram
                # silently logs the traceback without answering.
                db.commit()

            # If banned, answer and stop.
            if bu.banned:
                await msg.answer(
                    "Доступ заблокирован администратором за превышение лимита устройств."
                )
                return

            # Ensure the user has a client on every configured server
            # and the xray config on each is up to date. Idempotent.
            # Isolated failure mode: if reconcile blows up (e.g. agent
            # unreachable, server row inconsistent, schema drift), we
            # still want to greet the user so /start is never silent.
            try:
                issued = _ensure_bot_user_clients(db, bot_row, bu)
            except Exception as exc:
                log.exception(
                    "bot=%s user=%s: client reconcile failed: %s",
                    bot_id, u.id, exc,
                )
                issued = []
                # Expire the session so stale in-memory objects from the
                # failed flush don't poison subsequent queries in this
                # handler.
                try:
                    db.rollback()
                except Exception:
                    pass
            if not issued:
                note = (
                    "Пока нет доступных серверов — попробуй позже."
                    if is_new else
                    "Сервера временно недоступны — попробуй ещё раз через минуту."
                )
                await msg.answer(note, reply_markup=_main_keyboard())
                # Still commit audit / timestamp changes if the row
                # was new and reconcile failed halfway through.
                try:
                    db.commit()
                except Exception:
                    db.rollback()
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
                f"👋 <b>Привет, {u.first_name or 'друг'}!</b>\n\n"
                "🚀 Это <b>быстрый и стабильный VPN</b> на протоколе "
                "VLESS + Reality — трафик маскируется под обычный HTTPS, "
                "провайдер ничего не видит и не блокирует.\n\n"
                "💳 Жми «<b>Моя подписка</b>» — получи свою ссылку.\n"
                "📖 Не знаешь как подключиться? «<b>Инструкция</b>» поможет "
                "настроить Happ / v2rayN / sing-box за минуту.\n\n"
                "Любой вопрос — «<b>ℹ️ О сервисе</b>» → там контакты."
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
            # Two messages: the card + inline "Открыть ссылку" button,
            # then a reply-keyboard nudge so the user keeps the bottom
            # menu in view. Telegram doesn't allow mixing inline and
            # reply markups on the same message. Wrap the send in a
            # try/except: if Telegram rejects the inline button (e.g.
            # the admin configured a panel.public_url Telegram refuses,
            # or a future schema tweak trips BUTTON_URL_INVALID), we
            # still answer the user with the URL as plain text instead
            # of silently dropping the «Моя подписка» reply.
            card = _format_mysub(bu, clients, sub_url)
            try:
                await msg.answer(
                    card,
                    reply_markup=_mysub_keyboard(sub_url),
                    disable_web_page_preview=True,
                )
            except TelegramAPIError as exc:
                log.warning(
                    "mysub inline keyboard failed (bot=%s user=%s): %s — "
                    "falling back to plain text",
                    bot_id, bu.tg_user_id, exc,
                )
                try:
                    await msg.answer(card, disable_web_page_preview=True)
                except TelegramAPIError as exc2:
                    log.warning(
                        "mysub plain-text fallback failed (bot=%s user=%s): %s",
                        bot_id, bu.tg_user_id, exc2,
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
        await _send_buy_plans(msg)

    @router.callback_query(F.data == "buy:plans")
    async def on_cb_buy_plans(cb: CallbackQuery) -> None:  # pragma: no cover
        await cb.answer()
        if cb.message is not None:
            await _send_buy_plans(cb.message)

    @router.callback_query(F.data.startswith("buy:plan:"))
    async def on_cb_buy_plan(cb: CallbackQuery) -> None:  # pragma: no cover
        try:
            plan_id = int((cb.data or "").rsplit(":", 1)[1])
        except (ValueError, IndexError):
            await cb.answer()
            return
        await cb.answer()
        if cb.message is not None:
            await _send_provider_picker(cb.message, plan_id=plan_id)

    @router.callback_query(F.data.startswith("buy:go:"))
    async def on_cb_buy_go(cb: CallbackQuery) -> None:  # pragma: no cover
        """Plan + provider chosen → create Order + deliver invoice."""
        try:
            _, _, plan_id_s, provider = (cb.data or "").split(":", 3)
            plan_id = int(plan_id_s)
        except (ValueError, IndexError):
            await cb.answer()
            return
        if provider not in payments_mod.KNOWN_PROVIDERS:
            await cb.answer("Неизвестный способ оплаты.", show_alert=True)
            return
        if cb.from_user is None or cb.message is None:
            await cb.answer()
            return
        await cb.answer("Создаю счёт…")
        await _deliver_invoice(
            cb.message,
            tg_user_id=str(cb.from_user.id),
            plan_id=plan_id,
            provider=provider,
        )

    # ---------- Telegram Stars: pre-checkout + successful_payment
    @router.pre_checkout_query()
    async def on_pre_checkout(q: PreCheckoutQuery) -> None:  # pragma: no cover
        # Always accept — we already validated the order at invoice
        # creation time; rejecting here just confuses the user.
        try:
            await q.answer(ok=True)
        except TelegramAPIError as exc:
            log.warning("pre_checkout answer failed: %s", exc)

    @router.message(F.successful_payment)
    async def on_successful_payment(msg: Message) -> None:  # pragma: no cover
        sp = msg.successful_payment
        if sp is None:
            return
        payload = sp.invoice_payload or ""
        charge_id = (
            sp.telegram_payment_charge_id
            or sp.provider_payment_charge_id
            or ""
        )
        with SessionLocal() as db:
            try:
                order = payments_mod.handle_stars_successful_payment(
                    db, invoice_payload=payload, telegram_charge_id=charge_id,
                )
            except payments_mod.PaymentError as exc:
                log.warning("stars payment apply failed: %s", exc)
                order = None
        if order is not None:
            await msg.answer(
                _format_paid_confirmation(order),
                reply_markup=_main_keyboard(),
            )
        else:
            await msg.answer(
                "✅ Оплата получена — но не удалось сопоставить заказ. "
                "Напиши администратору.",
                reply_markup=_main_keyboard(),
            )

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

    @router.callback_query(F.data == "sub:help")
    async def on_cb_help_index(cb: CallbackQuery) -> None:  # pragma: no cover
        await cb.answer()
        if cb.message is not None:
            try:
                await cb.message.answer(
                    "📖 <b>Выбери платформу</b> — пришлю пошаговую инструкцию:",
                    reply_markup=_instructions_keyboard(),
                )
            except TelegramAPIError:
                pass

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


def _fmt_bytes_gb(num: int) -> str:
    """Render a byte count as ``X.XX ГБ`` with sensible precision.

    Very small values collapse to ``0 ГБ`` so a fresh key doesn't look
    like it leaked traffic — the raw counter lands at exactly 0 until
    xray flushes the first stat tick.
    """
    if not num or num <= 0:
        return "0 ГБ"
    gb = num / (1024 ** 3)
    if gb < 0.01:
        mb = num / (1024 ** 2)
        return f"{mb:.1f} МБ"
    return f"{gb:.2f} ГБ"


def _server_label_for_bot(server: "Optional[Server]") -> str:
    if server is None:
        return "?"
    return (getattr(server, "display_name", "") or "").strip() or server.name


def _format_mysub(
    bu: "TgBotUser", clients: "list[Client]", sub_url: str
) -> str:
    """Format the «Моя подписка» card in xankaVPN style.

    Layout:
        💳 Моя подписка

        🔗 <code>sub url</code>

        📊 Потрачено: 1.23 ГБ / 10 ГБ     ← aggregated across all keys
        📅 До: 24.12.2025 14:30 UTC       ← earliest expiry
        🌍 Серверы (3): DE 1, NL 2, SG 3

    Traffic figures come from xray's live counters
    (``Client.total_up`` + ``total_down``) — the same numbers the
    subscription endpoint exposes in ``Subscription-Userinfo`` so
    the bot card and the VPN client agree.
    """
    lines: list[str] = [
        "💳 <b>Моя подписка</b>",
        "",
        "🔗 <b>Ссылка:</b>",
        f"<code>{sub_url}</code>",
    ]

    if clients:
        up_sum = sum(int(c.total_up or 0) for c in clients)
        down_sum = sum(int(c.total_down or 0) for c in clients)
        used = up_sum + down_sum
        # ``data_limit_bytes`` is per-key in schema but in practice the
        # bot issues identical limits to every server for one user; the
        # user-facing quota is the largest configured limit, not the
        # sum, so Happ's "X of Y" matches Telegram's.
        limits = [int(c.data_limit_bytes or 0) for c in clients]
        limit_val = max(limits) if limits else 0

        if limit_val > 0:
            lines.append(
                f"\n📊 Трафик: <b>{_fmt_bytes_gb(used)}</b> "
                f"из <b>{_fmt_bytes_gb(limit_val)}</b>"
            )
        else:
            lines.append(
                f"\n📊 Трафик: <b>{_fmt_bytes_gb(used)}</b> "
                "(без лимита)"
            )

        # Earliest expiry across issued keys. Bots normally write the
        # same expiry on every server, but if the admin tweaks one
        # manually we show the soonest so the user isn't surprised.
        expiries = [c.expires_at for c in clients if c.expires_at is not None]
        if expiries:
            soonest = min(expiries)
            lines.append(
                f"📅 Действует до: <b>{soonest.strftime('%d.%m.%Y %H:%M')}</b> UTC"
            )
        else:
            lines.append("♾ Срок действия: <b>без ограничений</b>")

        names = sorted({_server_label_for_bot(c.server) for c in clients})
        if len(names) == 1:
            lines.append(f"🌍 Сервер: <b>{names[0]}</b>")
        else:
            lines.append(
                f"🌍 Серверы (<b>{len(names)}</b>): <b>{', '.join(names)}</b>"
            )

    lines.extend([
        "",
        "👇 Жми «📖 Инструкция по подключению», если ещё не настроил клиент.",
    ])
    return "\n".join(lines)


def _mysub_keyboard(sub_url: str) -> InlineKeyboardMarkup:
    """Inline buttons under the «Моя подписка» card.

    Telegram only accepts ``http(s)://`` / ``tg://`` schemes in
    inline-button URLs — anything else raises ``BUTTON_URL_INVALID``
    and Telegram drops the entire message, which is exactly how the
    previous ``happ://add/…`` link silently broke the «Моя подписка»
    reply. We expose the raw ``https://`` subscription URL; Happ +
    other VLESS clients register the standard ``https`` scheme via
    OS deep-linking and open it natively on tap. Desktop users just
    land on the panel's subscription endpoint and can copy from there.
    """
    return InlineKeyboardMarkup(inline_keyboard=[
        [
            InlineKeyboardButton(
                text="📲 Открыть ссылку подписки",
                url=sub_url,
            ),
        ],
        [
            InlineKeyboardButton(text="📖 Инструкция", callback_data="sub:help"),
        ],
    ])


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

_PARTNER_TEXT = (
    "🤝 <b>Партнёрская программа</b>\n\n"
    "Скоро: зарабатывай процент с оплат по твоей реферальной ссылке."
)


# ---------- payments: bot-side helpers ----------
def _active_plans(db: Session) -> list[Plan]:
    """Plans the user can actually buy right now.

    Filters disabled rows and rows where *every* provider price is
    zero (nothing sellable). Ordering mirrors the admin panel.
    """
    all_plans = list(
        db.scalars(
            select(Plan).order_by(Plan.sort_order.asc(), Plan.id.asc())
        ).all()
    )
    settings = payments_mod.load_settings(db)
    out: list[Plan] = []
    for p in all_plans:
        if not p.enabled:
            continue
        buyable_any = False
        for prov in payments_mod.KNOWN_PROVIDERS:
            if not payments_mod.provider_enabled(settings, prov):
                continue
            if payments_mod.plan_price_for_provider(p, prov) > 0:
                buyable_any = True
                break
        if buyable_any:
            out.append(p)
    return out


def _fmt_plan_price(plan: Plan) -> str:
    """Short-form price for the plan button — picks the best-known
    currency available to the end user (RUB wins if set, else USDT,
    else Stars)."""
    if plan.price_rub_kopecks:
        rub = plan.price_rub_kopecks / 100.0
        return f"{rub:.0f} ₽"
    if plan.price_crypto_usdt_cents:
        usdt = plan.price_crypto_usdt_cents / 100.0
        return f"{usdt:.2f} USDT"
    if plan.price_stars:
        return f"{plan.price_stars} ⭐"
    return "—"


def _plan_picker_keyboard(plans: list[Plan]) -> InlineKeyboardMarkup:
    rows = []
    for p in plans:
        label = f"{p.name} · {_fmt_plan_price(p)}"
        rows.append([InlineKeyboardButton(
            text=label, callback_data=f"buy:plan:{p.id}"
        )])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _provider_picker_keyboard(
    plan: Plan, settings: payments_mod.PaymentSettings
) -> InlineKeyboardMarkup:
    rows = []
    for prov in payments_mod.KNOWN_PROVIDERS:
        if not payments_mod.provider_enabled(settings, prov):
            continue
        price = payments_mod.plan_price_for_provider(plan, prov)
        if price <= 0:
            continue
        if prov == payments_mod.PROVIDER_STARS:
            suffix = f"{price} ⭐"
        elif prov == payments_mod.PROVIDER_CRYPTOBOT:
            suffix = f"{price / 100:.2f} USDT"
        else:  # freekassa
            suffix = f"{price / 100:.0f} ₽"
        text = f"{payments_mod.PROVIDER_LABELS[prov]} · {suffix}"
        rows.append([InlineKeyboardButton(
            text=text,
            callback_data=f"buy:go:{plan.id}:{prov}",
        )])
    rows.append([InlineKeyboardButton(
        text="« Назад к тарифам", callback_data="buy:plans"
    )])
    return InlineKeyboardMarkup(inline_keyboard=rows)


def _format_plan_summary(plan: Plan, bu_clients: list[Client]) -> str:
    """Header block before the provider picker.

    Calls out the current expiry and whether this would *extend* or
    *replace* (answering the user's "ask when buying again" setting
    in a passive way — there's only one action, we just tell them
    which.)
    """
    now = datetime.utcnow()
    expiries = [c.expires_at for c in bu_clients if c.expires_at is not None]
    soonest = min(expiries) if expiries else None
    lines = [
        f"💳 <b>Тариф:</b> {plan.name}",
        f"📅 <b>Длительность:</b> {plan.duration_days} дн.",
    ]
    if soonest and soonest > now:
        new_until = soonest + timedelta(days=int(plan.duration_days))
        lines.append(
            f"\nТвой ключ сейчас активен до <b>{soonest.strftime('%d.%m.%Y')}</b>.\n"
            f"После оплаты будет продлён до <b>{new_until.strftime('%d.%m.%Y')}</b>."
        )
    elif soonest:
        new_until = now + timedelta(days=int(plan.duration_days))
        lines.append(
            f"\nКлюч истёк <b>{soonest.strftime('%d.%m.%Y')}</b>. "
            f"После оплаты снова заработает до <b>{new_until.strftime('%d.%m.%Y')}</b>."
        )
    else:
        new_until = now + timedelta(days=int(plan.duration_days))
        lines.append(
            f"\nПосле оплаты ключ будет активен до "
            f"<b>{new_until.strftime('%d.%m.%Y')}</b>."
        )
    lines.append("\n👇 Выбери способ оплаты:")
    return "\n".join(lines)


def _format_paid_confirmation(order: Order) -> str:
    if order.plan_duration_days > 0:
        return (
            "✅ <b>Оплата прошла!</b>\n\n"
            f"Тариф <b>{order.plan_name}</b> активирован — "
            f"ключ продлён на <b>{order.plan_duration_days}</b> дн.\n\n"
            "Обнови подписку в клиенте (Happ / v2rayN / Hiddify) — и всё готово."
        )
    return "✅ <b>Оплата получена</b>, спасибо!"


async def _send_buy_plans(msg: Message, *, bot_id: Optional[int] = None) -> None:
    """Render the plan picker in response to «🛒 Купить подписку»."""
    # ``bot_id`` is optional because we also resolve it from the
    # current aiogram Bot token when called from a reply-keyboard
    # handler that doesn't pass it explicitly. For inline callbacks
    # the handler passes ``bot_id`` directly.
    with SessionLocal() as db:
        if bot_id is None:
            bot_id = _resolve_bot_id_from_message(db, msg)
        bot_row = db.get(TgBot, bot_id) if bot_id else None
        if bot_row is None or not bot_row.enabled:
            await msg.answer(
                "Бот отключён администратором.",
                reply_markup=_main_keyboard(),
            )
            return
        plans = _active_plans(db)
    if not plans:
        await msg.answer(
            "🛒 <b>Купить подписку</b>\n\n"
            "Пока ни один тариф не настроен. Вернись чуть позже — "
            "администратор скоро включит оплату.",
            reply_markup=_main_keyboard(),
        )
        return
    header = (
        "🛒 <b>Купить подписку</b>\n\n"
        "Выбери срок — дальше подскажу доступные способы оплаты."
    )
    await msg.answer(header, reply_markup=_plan_picker_keyboard(plans))


async def _send_provider_picker(msg: Message, *, plan_id: int) -> None:
    with SessionLocal() as db:
        plan = db.get(Plan, plan_id)
        if plan is None or not plan.enabled:
            await msg.answer(
                "Этот тариф больше недоступен. Выбери другой:",
                reply_markup=_main_keyboard(),
            )
            return
        settings = payments_mod.load_settings(db)
        bot_id = _resolve_bot_id_from_message(db, msg)
        bu_clients: list[Client] = []
        if bot_id:
            bu = _current_bot_user(db, bot_id, msg)
            if bu is not None:
                bu_clients = list(bu.clients)
                if bu.client_id and not bu_clients:
                    legacy = db.get(Client, bu.client_id)
                    if legacy is not None:
                        bu_clients = [legacy]
        summary = _format_plan_summary(plan, bu_clients)
    await msg.answer(summary, reply_markup=_provider_picker_keyboard(plan, settings))


async def _deliver_invoice(
    msg: Message, *, tg_user_id: str, plan_id: int, provider: str
) -> None:
    with SessionLocal() as db:
        bot_id = _resolve_bot_id_from_message(db, msg)
        bot_row = db.get(TgBot, bot_id) if bot_id else None
        if bot_row is None or not bot_row.enabled:
            await msg.answer(
                "Бот отключён администратором.",
                reply_markup=_main_keyboard(),
            )
            return
        plan = db.get(Plan, plan_id)
        if plan is None or not plan.enabled:
            await msg.answer("Этот тариф больше недоступен.")
            return
        bu = db.scalar(
            select(TgBotUser).where(
                TgBotUser.bot_id == bot_row.id,
                TgBotUser.tg_user_id == tg_user_id,
            )
        )
        if bu is None:
            await msg.answer("Сначала отправь /start.",
                             reply_markup=_main_keyboard())
            return
        if bu.banned:
            await msg.answer("Доступ заблокирован администратором.")
            return
        public_base = _subscription_base_url(db)
        try:
            inv = payments_mod.create_invoice(
                db,
                bot=bot_row,
                bot_user=bu,
                plan=plan,
                provider=provider,
                public_base_url=public_base,
            )
        except payments_mod.PaymentError as exc:
            await msg.answer(f"Не удалось создать счёт: {exc}")
            return
        except Exception as exc:  # pragma: no cover
            log.exception("create_invoice crashed: %s", exc)
            await msg.answer(
                "⚠️ Не удалось создать счёт — попробуй ещё раз через минуту."
            )
            return
        order_id = inv.order_id

    # Deliver the invoice according to the provider.
    if provider == payments_mod.PROVIDER_STARS:
        try:
            await msg.bot.send_invoice(
                chat_id=msg.chat.id,
                title=f"{plan.name}",
                description=f"Подписка на {plan.duration_days} дн.",
                payload=inv.stars_payload,
                currency="XTR",
                prices=[LabeledPrice(label=plan.name, amount=inv.amount_stars)],
            )
        except TelegramAPIError as exc:
            log.warning("send_invoice(stars) failed: %s", exc)
            await msg.answer(
                f"⚠️ Telegram отклонил счёт: <code>{exc}</code>. "
                "Попробуй ещё раз или выбери другой способ."
            )
            _mark_order_failed(order_id, reason=f"stars: {exc}")
            return
        return

    if provider in (payments_mod.PROVIDER_CRYPTOBOT, payments_mod.PROVIDER_FREEKASSA):
        pay_url = inv.pay_url
        label = (
            "🪙 Открыть CryptoBot"
            if provider == payments_mod.PROVIDER_CRYPTOBOT
            else "💳 Перейти к оплате"
        )
        if provider == payments_mod.PROVIDER_CRYPTOBOT:
            amount_txt = f"{inv.amount / 100:.2f} USDT"
        else:
            amount_txt = f"{inv.amount / 100:.0f} ₽"
        text = (
            f"💳 <b>Счёт создан</b>\n\n"
            f"Тариф: <b>{plan.name}</b> · {plan.duration_days} дн.\n"
            f"Сумма: <b>{amount_txt}</b>\n\n"
            "Нажми кнопку ниже, чтобы оплатить. После подтверждения "
            "оплаты ключ продлится автоматически — сюда придёт сообщение."
        )
        kb = InlineKeyboardMarkup(inline_keyboard=[[
            InlineKeyboardButton(text=label, url=pay_url),
        ]])
        try:
            await msg.answer(text, reply_markup=kb, disable_web_page_preview=True)
        except TelegramAPIError as exc:
            log.warning("deliver invoice(%s) failed: %s", provider, exc)
            await msg.answer(f"Ссылка на оплату: {pay_url}")
        return


def _mark_order_failed(order_id: int, *, reason: str) -> None:
    with SessionLocal() as db:
        order = db.get(Order, order_id)
        if order is None or order.status != "pending":
            return
        order.status = "failed"
        order.notes = reason[:1000]
        db.commit()


def _resolve_bot_id_from_message(db: Session, msg: Message) -> Optional[int]:
    """Find the DB ``TgBot.id`` matching the current aiogram Bot token.

    aiogram ``Message.bot`` is the ``Bot`` instance servicing that
    update. We match on its token — every ``TgBot`` row is keyed by
    token so this is unique.
    """
    bot = getattr(msg, "bot", None)
    if bot is None:
        return None
    token = getattr(bot, "token", "") or ""
    if not token:
        return None
    row = db.scalar(select(TgBot).where(TgBot.bot_token == token))
    return row.id if row is not None else None


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
        # Global fallback so a bug in any handler can't silently drop the
        # user's message. Without this, aiogram logs the traceback at
        # ERROR and answers nothing — which is what caused /start to
        # «ничего не отвечать» whenever the reconcile path raised.
        self.dp.errors.register(self._on_handler_error)
        self.task = asyncio.create_task(self._run(), name=f"tg-bot-{self.bot_id}")

    async def _on_handler_error(self, event: ErrorEvent) -> bool:
        log.exception(
            "bot=%s handler failed: %s",
            self.bot_id, event.exception,
        )
        upd = event.update
        # Best-effort user-visible reply so they don't think the bot is
        # frozen. Works for both Message and CallbackQuery updates.
        try:
            if upd is not None and upd.message is not None:
                await upd.message.answer(
                    "⚠️ Технический сбой, уже разбираемся. Попробуй ещё раз через минуту.",
                )
            elif upd is not None and upd.callback_query is not None:
                await upd.callback_query.answer(
                    "⚠️ Технический сбой, попробуй ещё раз.",
                    show_alert=True,
                )
        except Exception:
            # Deliberately broad: we're already in the fallback path.
            # If we can't even answer, just log and move on.
            log.debug("bot=%s error handler failed to reply", self.bot_id)
        return True  # tell aiogram: error handled, don't re-raise

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

    async def notify_payment_success(self, *, order_id: int) -> bool:
        """Send the «оплата прошла» confirmation to the buying user.

        Called from the CryptoBot / FreeKassa webhook handlers after
        :func:`payments.apply_payment` has extended the client. Returns
        True when the message actually left Telegram.
        """
        with SessionLocal() as db:
            order = db.get(Order, order_id)
            if order is None:
                return False
            if not order.bot_id or not order.bot_user_id:
                return False
            bot_row = db.get(TgBot, order.bot_id)
            bu = db.get(TgBotUser, order.bot_user_id)
            if bot_row is None or bu is None:
                return False
            tg_user_id = bu.tg_user_id
            text = _format_paid_confirmation(order)

        runner = self.runners.get(bot_row.id)
        if runner is None or runner.bot is None:
            return False
        try:
            await runner.bot.send_message(
                chat_id=tg_user_id, text=text,
            )
            return True
        except TelegramAPIError as exc:
            log.warning("payment-success notify failed: %s", exc)
            return False

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

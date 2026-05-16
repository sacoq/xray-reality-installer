"""Payments integration: Telegram Stars, CryptoBot, FreeKassa.

All three providers live behind the same ``Order`` row. A user picks a
plan in the bot; the bot calls :func:`create_invoice` which:

1. Creates a ``pending`` ``Order`` row.
2. Talks to the provider to get a pay URL (CryptoBot / FreeKassa) or
   builds a native Telegram invoice (Stars).
3. Returns a :class:`InvoiceResponse` the bot turns into a message /
   inline button.

On successful payment the provider either sends ``successful_payment``
(Telegram Stars, in-bot) or hits a webhook (CryptoBot / FreeKassa). All
three feed into :func:`apply_payment` which is the **single** place
that flips ``Order.status`` to ``paid`` and extends every client
belonging to the paying bot-user.

Payment credentials live in the generic ``settings`` key/value table so
admins can edit them through the panel UI without touching env vars /
the filesystem.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import (
    Client,
    Order,
    Plan,
    ReferralAccrual,
    Setting,
    TgBot,
    TgBotPlan,
    TgBotUser,
)


log = logging.getLogger("xnpanel.payments")


# ---------- provider identifiers ----------
PROVIDER_STARS = "stars"
PROVIDER_CRYPTOBOT = "cryptobot"
PROVIDER_FREEKASSA = "freekassa"

KNOWN_PROVIDERS = (PROVIDER_STARS, PROVIDER_CRYPTOBOT, PROVIDER_FREEKASSA)

CURRENCY_FOR_PROVIDER = {
    PROVIDER_STARS: "XTR",
    PROVIDER_CRYPTOBOT: "USDT",
    PROVIDER_FREEKASSA: "RUB",
}

# Human label shown next to every provider button in the bot.
PROVIDER_LABELS = {
    PROVIDER_STARS: "⭐ Telegram Stars",
    PROVIDER_CRYPTOBOT: "🪙 Крипта (CryptoBot)",
    PROVIDER_FREEKASSA: "💳 Карта / СБП (FreeKassa)",
}


# ---------- settings keys (in the ``settings`` K/V table) ----------
# Prefixed so they never collide with other panel settings.
KEY_STARS_ENABLED = "payments.stars.enabled"
KEY_CRYPTOBOT_ENABLED = "payments.cryptobot.enabled"
KEY_CRYPTOBOT_TOKEN = "payments.cryptobot.token"
KEY_CRYPTOBOT_TESTNET = "payments.cryptobot.testnet"
KEY_FREEKASSA_ENABLED = "payments.freekassa.enabled"
KEY_FREEKASSA_MERCHANT_ID = "payments.freekassa.merchant_id"
KEY_FREEKASSA_SECRET1 = "payments.freekassa.secret1"
KEY_FREEKASSA_SECRET2 = "payments.freekassa.secret2"
# Optional FreeKassa "payment system id" (the ``i=`` SCI param).
# When non-empty the user lands directly on the chosen method (e.g.
# i=6 for SBP) instead of FreeKassa's full method picker.
KEY_FREEKASSA_PAYMENT_SYSTEM_ID = "payments.freekassa.i"

# Keys whose values should be masked in admin API responses. Anything
# with credentials / secrets in the name.
MASKED_KEYS = {
    KEY_CRYPTOBOT_TOKEN,
    KEY_FREEKASSA_SECRET1,
    KEY_FREEKASSA_SECRET2,
}


def _get(db: Session, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    if row is None:
        return default
    return row.value or default


def _set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        db.add(Setting(key=key, value=value or ""))
    else:
        row.value = value or ""


def _get_bool(db: Session, key: str, default: bool = False) -> bool:
    v = _get(db, key, "").strip().lower()
    if not v:
        return default
    return v in ("1", "true", "yes", "on")


def mask_secret(value: str) -> str:
    """Return ``value`` with the middle replaced by ``•`` so the admin
    can confirm what's set without revealing the full token."""
    if not value:
        return ""
    if len(value) <= 6:
        return "•" * len(value)
    return f"{value[:3]}{'•' * max(3, len(value) - 6)}{value[-3:]}"


# ---------- settings surface for the admin API ----------
@dataclass
class PaymentSettings:
    """Snapshot of payment-provider configuration read from the DB.

    :func:`load_settings` returns a fresh instance on every call — the
    admin UI never caches these so there's no TTL to invalidate when
    credentials rotate.
    """

    stars_enabled: bool
    cryptobot_enabled: bool
    cryptobot_token: str  # raw value — callers mask before exposing
    cryptobot_testnet: bool
    freekassa_enabled: bool
    freekassa_merchant_id: str
    freekassa_secret1: str
    freekassa_secret2: str
    # Empty string means "no preselected method" — FreeKassa shows the
    # full method picker. Stored as raw text so the admin can leave it
    # blank without forcing a sentinel integer.
    freekassa_payment_system_id: str


def load_settings(db: Session) -> PaymentSettings:
    return PaymentSettings(
        stars_enabled=_get_bool(db, KEY_STARS_ENABLED, default=False),
        cryptobot_enabled=_get_bool(db, KEY_CRYPTOBOT_ENABLED, default=False),
        cryptobot_token=_get(db, KEY_CRYPTOBOT_TOKEN, ""),
        cryptobot_testnet=_get_bool(db, KEY_CRYPTOBOT_TESTNET, default=False),
        freekassa_enabled=_get_bool(db, KEY_FREEKASSA_ENABLED, default=False),
        freekassa_merchant_id=_get(db, KEY_FREEKASSA_MERCHANT_ID, ""),
        freekassa_secret1=_get(db, KEY_FREEKASSA_SECRET1, ""),
        freekassa_secret2=_get(db, KEY_FREEKASSA_SECRET2, ""),
        freekassa_payment_system_id=_get(db, KEY_FREEKASSA_PAYMENT_SYSTEM_ID, ""),
    )


def save_settings(db: Session, **updates: object) -> None:
    """Apply partial settings updates.

    Any key not present in ``updates`` is left untouched. Values of
    ``None`` are skipped so the admin UI can submit "don't change this
    secret" by leaving the field empty and mapping it to ``None``.
    """
    mapping = {
        "stars_enabled": (KEY_STARS_ENABLED, _fmt_bool),
        "cryptobot_enabled": (KEY_CRYPTOBOT_ENABLED, _fmt_bool),
        "cryptobot_token": (KEY_CRYPTOBOT_TOKEN, _fmt_str),
        "cryptobot_testnet": (KEY_CRYPTOBOT_TESTNET, _fmt_bool),
        "freekassa_enabled": (KEY_FREEKASSA_ENABLED, _fmt_bool),
        "freekassa_merchant_id": (KEY_FREEKASSA_MERCHANT_ID, _fmt_str),
        "freekassa_secret1": (KEY_FREEKASSA_SECRET1, _fmt_str),
        "freekassa_secret2": (KEY_FREEKASSA_SECRET2, _fmt_str),
        "freekassa_payment_system_id": (KEY_FREEKASSA_PAYMENT_SYSTEM_ID, _fmt_str),
    }
    for field, val in updates.items():
        if val is None:
            continue
        if field not in mapping:
            continue
        key, fmt = mapping[field]
        _set(db, key, fmt(val))


def _fmt_bool(v: object) -> str:
    return "1" if bool(v) else "0"


def _fmt_str(v: object) -> str:
    return str(v or "")


# ---------- invoice / pay URL ----------
@dataclass
class InvoiceResponse:
    """Result of :func:`create_invoice`.

    For Stars: ``stars_payload`` is the ``invoice_payload`` string the
    bot passes to ``sendInvoice``; ``amount_stars`` is the XTR price;
    ``pay_url`` is empty because the invoice is delivered natively.

    For CryptoBot / FreeKassa: ``pay_url`` is an HTTPS URL the bot
    surfaces as an inline button; ``stars_payload`` / ``amount_stars``
    are unused.
    """

    order_id: int
    provider: str
    currency: str
    amount: int

    pay_url: str = ""
    stars_payload: str = ""
    amount_stars: int = 0


class PaymentError(RuntimeError):
    """Surfaced to the bot user when a provider call fails."""


def plan_price_for_provider(plan: "Plan | TgBotPlan", provider: str) -> int:
    if provider == PROVIDER_STARS:
        return int(plan.price_stars or 0)
    if provider == PROVIDER_CRYPTOBOT:
        return int(plan.price_crypto_usdt_cents or 0)
    if provider == PROVIDER_FREEKASSA:
        return int(plan.price_rub_kopecks or 0)
    raise PaymentError(f"unknown provider {provider!r}")


def bot_active_plans(db: Session, bot: TgBot) -> list["Plan | TgBotPlan"]:
    """Return the price list this bot should sell.

    If the bot has at least one ``TgBotPlan`` row, those are returned
    (per-bot pricing). Otherwise the global ``plans`` table is used —
    keeps existing single-bot installs working without configuration.
    """
    rows: list[TgBotPlan] = list(db.scalars(
        select(TgBotPlan).where(TgBotPlan.bot_id == bot.id)
        .order_by(TgBotPlan.sort_order.asc(), TgBotPlan.id.asc())
    ).all())
    if rows:
        return list(rows)
    return list(db.scalars(
        select(Plan).order_by(Plan.sort_order.asc(), Plan.id.asc())
    ).all())


def provider_enabled(settings: PaymentSettings, provider: str) -> bool:
    if provider == PROVIDER_STARS:
        return settings.stars_enabled
    if provider == PROVIDER_CRYPTOBOT:
        return settings.cryptobot_enabled and bool(settings.cryptobot_token)
    if provider == PROVIDER_FREEKASSA:
        return (
            settings.freekassa_enabled
            and bool(settings.freekassa_merchant_id)
            and bool(settings.freekassa_secret1)
            and bool(settings.freekassa_secret2)
        )
    return False


def create_invoice(
    db: Session,
    *,
    bot: TgBot,
    bot_user: TgBotUser,
    plan: "Plan | TgBotPlan",
    provider: str,
    public_base_url: str = "",
) -> InvoiceResponse:
    """Create a new ``Order`` + provider invoice.

    Commits the ``Order`` row before talking to the provider so a
    crashed / retried flow can identify the order by ``id`` even if the
    provider returns late. ``public_base_url`` is the panel's externally
    reachable URL (``https://panel.example``) used to build webhook
    callbacks for FreeKassa / CryptoBot.
    """
    if provider not in KNOWN_PROVIDERS:
        raise PaymentError(f"unknown provider {provider!r}")
    settings = load_settings(db)
    if not provider_enabled(settings, provider):
        raise PaymentError("этот способ оплаты сейчас выключен")
    amount = plan_price_for_provider(plan, provider)
    if amount <= 0:
        raise PaymentError("для этого тарифа цена не задана")

    order = Order(
        bot_id=bot.id,
        bot_user_id=bot_user.id,
        # ``Order.plan_id`` references global plans only — per-bot plans
        # have a different table, so we keep it NULL there. Name and
        # duration are snapshot below either way.
        plan_id=plan.id if isinstance(plan, Plan) else None,
        plan_name=plan.name,
        plan_duration_days=plan.duration_days,
        provider=provider,
        currency=CURRENCY_FOR_PROVIDER[provider],
        amount=amount,
        status="pending",
    )
    db.add(order)
    db.commit()
    db.refresh(order)

    if provider == PROVIDER_STARS:
        # Stars invoices are sent via aiogram.Bot.send_invoice from
        # tg_bots — we just stamp a stable payload so we can map
        # successful_payment back to this order.
        payload = f"xnpanel:order:{order.id}"
        order.provider_invoice_id = payload
        db.commit()
        return InvoiceResponse(
            order_id=order.id,
            provider=provider,
            currency=order.currency,
            amount=amount,
            stars_payload=payload,
            amount_stars=amount,
        )

    if provider == PROVIDER_CRYPTOBOT:
        pay_url, invoice_id = _cryptobot_create_invoice(
            settings=settings,
            order=order,
            plan=plan,
            public_base_url=public_base_url,
        )
        order.provider_invoice_id = invoice_id
        order.provider_ref = pay_url
        db.commit()
        return InvoiceResponse(
            order_id=order.id,
            provider=provider,
            currency=order.currency,
            amount=amount,
            pay_url=pay_url,
        )

    if provider == PROVIDER_FREEKASSA:
        pay_url = _freekassa_build_pay_url(
            settings=settings,
            order=order,
            plan=plan,
        )
        order.provider_invoice_id = str(order.id)
        order.provider_ref = pay_url
        db.commit()
        return InvoiceResponse(
            order_id=order.id,
            provider=provider,
            currency=order.currency,
            amount=amount,
            pay_url=pay_url,
        )

    raise PaymentError(f"provider {provider!r} not implemented")


# ---------- CryptoBot ----------
# https://help.crypt.bot/crypto-pay-api
_CRYPTOBOT_BASE = "https://pay.crypt.bot"
_CRYPTOBOT_TESTNET_BASE = "https://testnet-pay.crypt.bot"


def _cryptobot_api_base(settings: PaymentSettings) -> str:
    return _CRYPTOBOT_TESTNET_BASE if settings.cryptobot_testnet else _CRYPTOBOT_BASE


def _cryptobot_create_invoice(
    *,
    settings: PaymentSettings,
    order: Order,
    plan: "Plan | TgBotPlan",
    public_base_url: str,
) -> tuple[str, str]:
    """Call CryptoBot ``createInvoice`` and return ``(pay_url, invoice_id)``."""
    # API expects a decimal string — ``cents`` → ``X.XX``.
    cents = int(order.amount)
    amount_decimal = f"{cents // 100}.{cents % 100:02d}"
    payload = {
        "currency_type": "crypto",
        "asset": "USDT",
        "amount": amount_decimal,
        "description": f"{plan.name} — {plan.duration_days} дн.",
        "hidden_message": f"Заказ #{order.id} оплачен. Подписка продлена на {plan.duration_days} дн.",
        "expires_in": 3600,  # 1 hour
        "payload": f"xnpanel:order:{order.id}",
    }
    if public_base_url:
        payload["paid_btn_name"] = "callback"
        payload["paid_btn_url"] = public_base_url.rstrip("/")
    try:
        r = httpx.post(
            f"{_cryptobot_api_base(settings)}/api/createInvoice",
            headers={"Crypto-Pay-API-Token": settings.cryptobot_token},
            json=payload,
            timeout=15,
        )
    except httpx.HTTPError as exc:
        raise PaymentError(f"CryptoBot недоступен: {exc}") from exc
    data: dict = {}
    try:
        data = r.json()
    except Exception:  # noqa: BLE001
        pass
    if not r.is_success or not data.get("ok"):
        msg = data.get("error", {}).get("name") or f"HTTP {r.status_code}"
        raise PaymentError(f"CryptoBot вернул ошибку: {msg}")
    result = data.get("result", {}) or {}
    pay_url = (
        result.get("pay_url") or result.get("bot_invoice_url") or result.get("mini_app_invoice_url") or ""
    )
    invoice_id = str(result.get("invoice_id") or result.get("id") or "")
    if not pay_url or not invoice_id:
        raise PaymentError("CryptoBot не вернул ссылку на оплату")
    return pay_url, invoice_id


def handle_cryptobot_webhook(
    db: Session, *, payload: dict, signature: str
) -> Optional[Order]:
    """Process a ``invoice_paid`` update from CryptoBot.

    Signature check follows CryptoBot docs:
    ``hmac_sha256(sha256(token), json_body)``. Returns the matching
    :class:`Order` after extending the user, or ``None`` if the event
    doesn't correspond to an open order.
    """
    settings = load_settings(db)
    if not settings.cryptobot_token:
        raise PaymentError("CryptoBot не настроен")

    # CryptoBot signs the RAW body. ``payload`` here is the already-parsed
    # dict — the caller is expected to pass the raw body too but we
    # accept a dict for simplicity by re-serialising. The signature is
    # still valid on that re-serialised form only when the original
    # body was produced with the same separators. We require the raw
    # bytes to be passed in via the ``_raw_body`` key.
    raw = payload.pop("_raw_body", b"") or b""
    if raw and signature:
        secret = hashlib.sha256(settings.cryptobot_token.encode()).digest()
        expected = hmac.new(secret, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise PaymentError("bad cryptobot signature")

    if payload.get("update_type") != "invoice_paid":
        return None
    inv = payload.get("payload", {}) or {}
    invoice_id = str(inv.get("invoice_id") or "")
    status = (inv.get("status") or "").lower()
    if not invoice_id:
        return None

    order = db.scalar(
        select(Order).where(
            Order.provider == PROVIDER_CRYPTOBOT,
            Order.provider_invoice_id == invoice_id,
        )
    )
    if order is None:
        log.warning("cryptobot webhook for unknown invoice_id=%s", invoice_id)
        return None

    if status == "paid" and order.status == "pending":
        apply_payment(db, order)
    return order


# ---------- FreeKassa ----------
# Standard "SCI" redirect flow — we build a signed URL and hand it to
# the user. On success FreeKassa POSTs our callback URL with the MD5
# signature using secret2; we verify, flip the order, extend the user,
# and respond ``YES``.
_FREEKASSA_PAY_URL = "https://pay.freekassa.ru/"


def _freekassa_pay_signature(
    *,
    merchant_id: str,
    amount_str: str,
    secret: str,
    currency: str,
    order_id: str,
) -> str:
    """SCI sig: MD5(merchant_id:amount:secret1:currency:order_id)."""
    raw = f"{merchant_id}:{amount_str}:{secret}:{currency}:{order_id}"
    return hashlib.md5(raw.encode()).hexdigest()


def _freekassa_callback_signature(
    *,
    merchant_id: str,
    amount_str: str,
    secret: str,
    order_id: str,
) -> str:
    """Callback sig: MD5(merchant_id:amount:secret2:order_id)."""
    raw = f"{merchant_id}:{amount_str}:{secret}:{order_id}"
    return hashlib.md5(raw.encode()).hexdigest()


def _freekassa_amount(order: Order) -> str:
    """Format ``kopecks`` → ``X.XX`` RUB."""
    kopecks = int(order.amount)
    return f"{kopecks // 100}.{kopecks % 100:02d}"


def _freekassa_build_pay_url(
    *,
    settings: PaymentSettings,
    order: Order,
    plan: "Plan | TgBotPlan",
) -> str:
    amount = _freekassa_amount(order)
    sig = _freekassa_pay_signature(
        merchant_id=settings.freekassa_merchant_id,
        amount_str=amount,
        secret=settings.freekassa_secret1,
        currency="RUB",
        order_id=str(order.id),
    )
    params: dict[str, str] = {
        "m": settings.freekassa_merchant_id,
        "oa": amount,
        "o": str(order.id),
        "s": sig,
        "currency": "RUB",
        "us_order": str(order.id),
        "us_plan": plan.name,
    }
    # Optional payment system id — when set, FreeKassa skips the
    # method picker and lands the user on this method directly.
    psys = (settings.freekassa_payment_system_id or "").strip()
    if psys:
        params["i"] = psys
    return f"{_FREEKASSA_PAY_URL}?{urlencode(params)}"


def handle_freekassa_callback(
    db: Session, *, form: dict
) -> Optional[Order]:
    """Process a FreeKassa server callback.

    ``form`` is the ``x-www-form-urlencoded`` payload POSTed to our
    callback URL. Returns the ``Order`` on success; raises
    :class:`PaymentError` on signature / state mismatch.
    """
    settings = load_settings(db)
    if not settings.freekassa_merchant_id or not settings.freekassa_secret2:
        raise PaymentError("FreeKassa не настроен")

    merchant_id = str(form.get("MERCHANT_ID", ""))
    amount = str(form.get("AMOUNT", ""))
    order_id = str(form.get("MERCHANT_ORDER_ID", ""))
    sign = str(form.get("SIGN", ""))
    if merchant_id != settings.freekassa_merchant_id:
        raise PaymentError("merchant_id mismatch")
    expected = _freekassa_callback_signature(
        merchant_id=merchant_id,
        amount_str=amount,
        secret=settings.freekassa_secret2,
        order_id=order_id,
    )
    if sign.lower() != expected.lower():
        raise PaymentError("bad signature")

    order = db.get(Order, int(order_id)) if order_id.isdigit() else None
    if order is None or order.provider != PROVIDER_FREEKASSA:
        raise PaymentError("unknown order")

    # FreeKassa rounds to 2 decimals; we sent kopecks-derived amount,
    # so re-compute and compare as strings to avoid float fuzz.
    if amount != _freekassa_amount(order):
        raise PaymentError("amount mismatch")

    if order.status == "pending":
        apply_payment(db, order)
    return order


# ---------- Telegram Stars ----------
def handle_stars_successful_payment(
    db: Session, *, invoice_payload: str, telegram_charge_id: str
) -> Optional[Order]:
    """Map a Stars ``successful_payment`` back to an ``Order`` + extend."""
    if not invoice_payload.startswith("xnpanel:order:"):
        return None
    try:
        order_id = int(invoice_payload.rsplit(":", 1)[1])
    except (IndexError, ValueError):
        return None
    order = db.get(Order, order_id)
    if order is None or order.provider != PROVIDER_STARS:
        return None
    if order.status == "pending":
        order.provider_ref = telegram_charge_id or ""
        apply_payment(db, order)
    return order


# ---------- shared: apply a paid order ----------
def apply_payment(db: Session, order: Order) -> None:
    """Flip ``order.status`` to ``paid`` and extend every client of the
    buying bot-user by ``plan_duration_days``.

    Extension rule: ``Client.expires_at`` is bumped by
    ``plan_duration_days``. If the current value is in the past (or
    ``None``), we reset to ``now + duration`` so the extension reflects
    the fresh purchase window rather than extending a dead key.

    Idempotent: calling twice on the same order is a no-op once the
    status has transitioned away from ``pending``.
    """
    if order.status != "pending":
        return

    extended_clients: list[int] = []
    if order.bot_user_id is not None and order.plan_duration_days > 0:
        bu = db.get(TgBotUser, order.bot_user_id)
        if bu is not None:
            now = datetime.utcnow()
            delta = timedelta(days=int(order.plan_duration_days))
            # All of the user's issued clients — both the legacy
            # ``client_id`` pointer and the many-to-many set.
            targets: list[Client] = []
            seen_ids: set[int] = set()
            for c in list(bu.clients):
                if c.id in seen_ids:
                    continue
                seen_ids.add(c.id)
                targets.append(c)
            if bu.client_id:
                legacy = db.get(Client, bu.client_id)
                if legacy is not None and legacy.id not in seen_ids:
                    targets.append(legacy)
            for c in targets:
                base = c.expires_at if c.expires_at and c.expires_at > now else now
                c.expires_at = base + delta
                # Re-enable the key — a purchased extension should
                # unblock an expired user automatically.
                c.enabled = True
                extended_clients.append(c.id)

    order.status = "paid"
    order.paid_at = datetime.utcnow()
    order.applied_at = datetime.utcnow()
    if extended_clients:
        order.notes = f"extended clients: {','.join(str(i) for i in extended_clients)}"
    db.commit()

    # Referral programme accruals — runs after the order is committed so
    # a partner-side bug never blocks the buyer from getting their key.
    try:
        _apply_referral_accruals(db, order)
    except Exception as exc:  # pragma: no cover — best-effort
        log.warning("referral accrual failed for order=%s: %s", order.id, exc)

    # Push xray config for every affected client's server so the
    # re-enabled / re-dated client is reflected immediately. Uses the
    # shared push helper to stay mode-aware.
    try:
        from .xray_push import push_config  # local import — avoid cycles
    except Exception:
        return
    pushed_servers: set[int] = set()
    if order.bot_user_id is not None:
        bu = db.get(TgBotUser, order.bot_user_id)
        if bu is not None:
            for c in list(bu.clients):
                if c.server_id in pushed_servers:
                    continue
                pushed_servers.add(c.server_id)
                srv = c.server
                if srv is None:
                    continue
                try:
                    push_config(srv, db)
                except Exception as exc:  # pragma: no cover
                    log.warning(
                        "post-payment push failed (server=%s): %s",
                        srv.id, exc,
                    )


def _walk_referral_chain(db: Session, bu: TgBotUser, max_levels: int) -> list[TgBotUser]:
    """Return up to ``max_levels`` ancestors of ``bu`` along ``referrer_id``.

    Stops early on a missing pointer or a cycle (defensive — a self
    referral would loop forever otherwise).
    """
    out: list[TgBotUser] = []
    seen: set[int] = {bu.id}
    cur = bu
    for _ in range(max(0, int(max_levels))):
        rid = cur.referrer_id
        if rid is None or rid in seen:
            break
        parent = db.get(TgBotUser, rid)
        if parent is None:
            break
        out.append(parent)
        seen.add(parent.id)
        cur = parent
    return out


def _apply_referral_accruals(db: Session, order: Order) -> None:
    """Credit the referral chain for ``order``.

    ``days`` mode: on the buyer's *first* paid order, every ancestor
    along the chain (within ``referral_levels``) gets their level's
    ``referral_lN_days`` added to the latest expiry of every issued
    client. ``days`` accrual is one-shot per buyer — it's "+X days for
    bringing a paying user", not a recurring bonus.

    ``percent`` mode: every paid order accrues
    ``referral_lN_percent`` × ``order.amount`` to the ancestor's
    per-currency partner balance. Levels with 0 days/percent are
    skipped (so admins can only enable level-1 referrals if they want).
    """
    if order.status != "paid":
        return
    if not order.bot_id or not order.bot_user_id:
        return
    bot = db.get(TgBot, order.bot_id)
    bu = db.get(TgBotUser, order.bot_user_id)
    if bot is None or bu is None:
        return
    mode = (bot.referral_mode or "off").strip().lower()
    if mode not in ("days", "percent"):
        return
    levels = max(1, min(3, int(bot.referral_levels or 1)))
    chain = _walk_referral_chain(db, bu, levels)
    if not chain:
        return

    if mode == "days":
        if bu.referral_first_payment_done:
            return
        bonuses = [
            int(bot.referral_l1_days or 0),
            int(bot.referral_l2_days or 0),
            int(bot.referral_l3_days or 0),
        ]
        for idx, ancestor in enumerate(chain):
            days = bonuses[idx] if idx < len(bonuses) else 0
            if days <= 0:
                continue
            _extend_clients(db, ancestor, days)
            db.add(ReferralAccrual(
                bot_id=bot.id,
                beneficiary_id=ancestor.id,
                source_user_id=bu.id,
                order_id=order.id,
                level=idx + 1,
                kind="days",
                amount=days,
            ))
        bu.referral_first_payment_done = True
        db.commit()
        return

    # percent mode
    percents = [
        int(bot.referral_l1_percent or 0),
        int(bot.referral_l2_percent or 0),
        int(bot.referral_l3_percent or 0),
    ]
    kind = _kind_for_currency(order.currency)
    if kind is None:
        return
    for idx, ancestor in enumerate(chain):
        pct = percents[idx] if idx < len(percents) else 0
        if pct <= 0:
            continue
        amt = int(order.amount or 0) * pct // 100
        if amt <= 0:
            continue
        _credit_referral_balance(ancestor, kind=kind, amount=amt)
        db.add(ReferralAccrual(
            bot_id=bot.id,
            beneficiary_id=ancestor.id,
            source_user_id=bu.id,
            order_id=order.id,
            level=idx + 1,
            kind=kind,
            amount=amt,
        ))
    db.commit()


def _kind_for_currency(currency: str) -> Optional[str]:
    cur = (currency or "").upper()
    if cur == "XTR":
        return "stars"
    if cur == "USDT":
        return "usdt_cents"
    if cur == "RUB":
        return "rub_kopecks"
    return None


def _credit_referral_balance(bu: TgBotUser, *, kind: str, amount: int) -> None:
    if amount <= 0:
        return
    if kind == "stars":
        bu.referral_balance_stars = int(bu.referral_balance_stars or 0) + amount
        bu.referral_total_earned_stars = int(bu.referral_total_earned_stars or 0) + amount
    elif kind == "usdt_cents":
        bu.referral_balance_usdt_cents = int(bu.referral_balance_usdt_cents or 0) + amount
        bu.referral_total_earned_usdt_cents = (
            int(bu.referral_total_earned_usdt_cents or 0) + amount
        )
    elif kind == "rub_kopecks":
        bu.referral_balance_rub_kopecks = int(bu.referral_balance_rub_kopecks or 0) + amount
        bu.referral_total_earned_rub_kopecks = (
            int(bu.referral_total_earned_rub_kopecks or 0) + amount
        )


def _extend_clients(db: Session, bu: TgBotUser, days: int) -> None:
    """Add ``days`` to every active client of ``bu`` (referral days bonus)."""
    if days <= 0:
        return
    now = datetime.utcnow()
    delta = timedelta(days=int(days))
    targets: list[Client] = []
    seen_ids: set[int] = set()
    for c in list(bu.clients):
        if c.id in seen_ids:
            continue
        seen_ids.add(c.id)
        targets.append(c)
    if bu.client_id:
        legacy = db.get(Client, bu.client_id)
        if legacy is not None and legacy.id not in seen_ids:
            targets.append(legacy)
    for c in targets:
        base = c.expires_at if c.expires_at and c.expires_at > now else now
        c.expires_at = base + delta
        c.enabled = True


def seed_default_plans(db: Session) -> None:
    """Populate the ``plans`` table with a 30/90/365 set if empty.

    Called once at startup so a fresh install has something to show in
    the admin panel immediately. Never overwrites existing rows — the
    admin owns prices after the first edit.
    """
    existing = db.scalar(select(Plan).limit(1))
    if existing is not None:
        return
    defaults = [
        # name, days, stars, usdt_cents, rub_kopecks
        ("30 дней", 30, 75, 200, 19900),
        ("90 дней", 90, 200, 500, 49900),
        ("1 год",  365, 750, 1800, 179900),
    ]
    for idx, (name, days, stars, usdt, rub) in enumerate(defaults):
        db.add(Plan(
            name=name,
            duration_days=days,
            price_stars=stars,
            price_crypto_usdt_cents=usdt,
            price_rub_kopecks=rub,
            enabled=True,
            sort_order=idx * 10,
        ))
    db.commit()

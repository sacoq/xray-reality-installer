"""Audit log + Telegram notifier helpers.

The panel records every mutating admin action as a row in ``audit_logs``.
The same helper optionally forwards important events to Telegram when a
bot_token + chat_id are configured in the Settings table.
"""
from __future__ import annotations

import json
import html
import logging
from typing import Any, Iterable, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, Setting, User
from .schemas import NotificationPreferences


log = logging.getLogger("xnpanel.audit")


# Subset of actions that should be pushed to Telegram. Audit log captures
# *everything*; Telegram only gets high-signal events so the chat stays
# readable.
_NOTIFY_ACTIONS = {
    "client.create",
    "client.bulk_create",
    "client.delete",
    "client.bulk_delete",
    "client.disabled_automatically",  # hit quota / expired
    "server.create",
    "server.delete",
    "server.reboot",
    "server.offline",
    "server.tspu_blocked",
}


def record(
    db: Session,
    *,
    user: Optional[User],
    action: str,
    resource_type: str = "",
    resource_id: Any = "",
    details: str = "",
    notify: Optional[bool] = None,
) -> AuditLog:
    """Write one audit row. If ``notify`` is True (or None and the action is
    in the default notify set) and Telegram is configured, also push a
    short notification to the admin's chat. Failures to notify must never
    break the caller — they're logged at WARNING and swallowed.
    """
    row = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "system",
        action=action,
        resource_type=resource_type,
        resource_id=str(resource_id) if resource_id not in (None, "") else "",
        details=details or "",
    )
    db.add(row)
    db.flush()

    should_notify = notify if notify is not None else (action in _NOTIFY_ACTIONS)
    if should_notify and notification_allowed(db, action):
        try:
            _telegram_notify(db, action=action, resource_type=resource_type,
                             resource_id=row.resource_id, details=details,
                             actor=row.username)
        except Exception as exc:  # pragma: no cover — never break on notifier failure
            log.warning("telegram notify failed: %s", exc)
    return row


def setting_get(db: Session, key: str, default: str = "") -> str:
    row = db.get(Setting, key)
    return row.value if row else default


def setting_set(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value)
        db.add(row)
    else:
        row.value = value


def telegram_config(db: Session) -> tuple[str, str]:
    """Return (bot_token, chat_id) from Settings. Either may be ''."""
    return setting_get(db, "telegram.bot_token"), setting_get(db, "telegram.chat_id")


def notification_preferences(db: Session) -> dict:
    try:
        return NotificationPreferences.model_validate_json(setting_get(db, 'notifications.preferences', '{}')).model_dump()
    except ValueError:
        return NotificationPreferences().model_dump()


def notification_allowed(db: Session, action: str) -> bool:
    prefs = notification_preferences(db)
    category = {'server.offline':'node_down', 'server.online':'node_up',
                'server.telemetry_lost':'telemetry_lost', 'server.online_drop':'online_drop',
                'server.online_recovery':'online_recovery', 'server.resource_pressure':'resource_pressure',
                'server.resource_recovery':'resource_pressure', 'server.tspu_blocked':'tspu',
                'client.disabled_automatically':'client_expiry'}.get(action)
    if category is None:
        category = 'client_actions' if action.startswith('client.') else ('server_actions' if action.startswith('server.') else 'other_events')
    return prefs['enabled'] and prefs[category]


def _telegram_notify(
    db: Session,
    *,
    action: str,
    resource_type: str,
    resource_id: str,
    details: str,
    actor: str,
) -> None:
    bot_token, chat_id = telegram_config(db)
    if not bot_token or not chat_id:
        return

    if not notification_allowed(db, action):
        return
    titles = {'server.offline':'🔴 Нода недоступна', 'server.online':'🟢 Нода восстановилась',
              'server.telemetry_lost':'🟠 Нет телеметрии ноды', 'server.online_drop':'📉 Резко снизился онлайн',
              'server.online_recovery':'📈 Онлайн восстановился', 'server.resource_pressure':'⚠️ Высокая нагрузка ноды',
              'server.resource_recovery':'✅ Нагрузка нормализовалась', 'server.tspu_blocked':'🛡 Обнаружена блокировка ноды'}
    parts: list[str] = [f"<b>{html.escape(titles.get(action, action))}</b>"]
    if resource_type:
        ref = f"{resource_type}#{resource_id}" if resource_id else resource_type
        parts.append(html.escape(ref))
    if details:
        parts.append(html.escape(details[:3000]))
    parts.append(f"— {html.escape(actor)}")
    text = "\n".join(parts)

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        response = httpx.post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": True},
            timeout=4.0,
        )
        if not response.is_success:
            log.warning('Telegram delivery failed, HTTP %s', response.status_code)
    except httpx.HTTPError as exc:
        log.warning("telegram sendMessage failed: %s", type(exc).__name__)


def telegram_test(db: Session, text: str = "xnPanel: test notification ✓") -> bool:
    """Send a one-off message. Used by the 'Test' button in the UI.
    Returns True on 2xx, False otherwise."""
    bot_token, chat_id = telegram_config(db)
    if not bot_token or not chat_id:
        return False
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        r = httpx.post(
            url,
            json={"chat_id": chat_id, "text": text, "disable_web_page_preview": True},
            timeout=6.0,
        )
        return r.status_code // 100 == 2
    except httpx.HTTPError:
        return False

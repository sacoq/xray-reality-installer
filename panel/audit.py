"""Audit log + Telegram notifier helpers.

The panel records every mutating admin action as a row in ``audit_logs``.
The same helper optionally forwards important events to Telegram when a
bot_token + chat_id are configured in the Settings table.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Iterable, Optional

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from .models import AuditLog, Setting, User


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
    if should_notify:
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

    parts: list[str] = [f"<b>{action}</b>"]
    if resource_type:
        ref = f"{resource_type}#{resource_id}" if resource_id else resource_type
        parts.append(ref)
    if details:
        parts.append(details)
    parts.append(f"— {actor}")
    text = "\n".join(parts)

    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    try:
        httpx.post(
            url,
            json={"chat_id": chat_id, "text": text, "parse_mode": "HTML",
                  "disable_web_page_preview": True},
            timeout=4.0,
        )
    except httpx.HTTPError as exc:
        log.warning("telegram sendMessage failed: %s", exc)


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

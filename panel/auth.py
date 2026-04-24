"""Auth helpers: password hashing + cookie-signed sessions."""
from __future__ import annotations

import hashlib
import hmac
import os
from typing import Optional

from fastapi import Depends, HTTPException, Request
from itsdangerous import BadSignature, URLSafeTimedSerializer
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from datetime import datetime

from sqlalchemy import select

from .database import get_db
from .models import ApiToken, User


SESSION_COOKIE = "xraypanel_session"
SESSION_MAX_AGE = 7 * 24 * 3600  # 7 days


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def _secret_key() -> str:
    key = os.environ.get("PANEL_SECRET_KEY", "").strip()
    if not key:
        # Stable fallback derived from hostname so sessions survive restarts
        # on a single host even if the env var is missing. Still: the installer
        # ALWAYS sets PANEL_SECRET_KEY.
        h = hashlib.sha256(b"xray-panel:" + os.uname().nodename.encode()).hexdigest()
        return h
    return key


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(_secret_key(), salt="xraypanel.session.v1")


def hash_password(raw: str) -> str:
    return pwd_context.hash(raw)


def verify_password(raw: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(raw, hashed)
    except Exception:
        return False


def issue_session(user_id: int) -> str:
    return _serializer().dumps({"uid": user_id})


def read_session(token: str) -> Optional[int]:
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE)
    except BadSignature:
        return None
    uid = data.get("uid") if isinstance(data, dict) else None
    if not isinstance(uid, int):
        return None
    return uid


def _bearer_user(request: Request, db: Session) -> Optional[User]:
    """Resolve `Authorization: Bearer <api-token>` against the api_tokens table.

    Returns the owning User if the token is valid, otherwise None. Updates
    the token's last_used_at on successful match (best-effort — failures
    here should never block the request).
    """
    header = request.headers.get("authorization") or request.headers.get("Authorization")
    if not header:
        return None
    parts = header.strip().split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    raw = parts[1].strip()
    if not raw:
        return None
    row = db.scalar(select(ApiToken).where(ApiToken.token == raw))
    if row is None:
        return None
    user = db.get(User, row.user_id)
    if user is None:
        return None
    try:
        row.last_used_at = datetime.utcnow()
        db.commit()
    except Exception:
        db.rollback()
    return user


def current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    # Prefer session cookie (browser), fall back to Bearer token (automation).
    token = request.cookies.get(SESSION_COOKIE) or ""
    uid = read_session(token) if token else None
    if uid is not None:
        user = db.get(User, uid)
        if user is not None:
            return user

    bearer = _bearer_user(request, db)
    if bearer is not None:
        return bearer

    raise HTTPException(status_code=401, detail="not authenticated")


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

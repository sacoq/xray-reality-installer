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

from .database import get_db
from .models import User


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


def current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> User:
    token = request.cookies.get(SESSION_COOKIE) or ""
    uid = read_session(token) if token else None
    if uid is None:
        raise HTTPException(status_code=401, detail="not authenticated")
    user = db.get(User, uid)
    if user is None:
        raise HTTPException(status_code=401, detail="user not found")
    return user


def constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())

"""xray-panel FastAPI application.

Routes:
- GET  /                       → redirect to /ui
- GET  /ui                     → main SPA shell (served as HTML)
- GET  /ui/login               → login page
- POST /api/auth/login         → authenticate, set session cookie
- POST /api/auth/logout        → clear session
- POST /api/auth/password      → change password
- GET  /api/servers            → list servers (with live status)
- POST /api/servers            → add a new server (registers agent + pushes first config)
- GET  /api/servers/{id}       → server detail + clients
- PATCH /api/servers/{id}      → update server fields
- DELETE /api/servers/{id}
- POST /api/servers/{id}/xray/{action}   → restart|start|stop xray on the node
- GET  /api/servers/{id}/xray/logs       → journalctl -u xray -n N
- POST /api/servers/{id}/reboot          → reboot the host
- POST /api/servers/{id}/rotate-keys     → regenerate x25519 + push config
- GET  /api/servers/{id}/stats → traffic + sysinfo
- GET  /api/servers/{id}/clients
- POST /api/servers/{id}/clients
- DELETE /api/servers/{id}/clients/{client_id}
- GET  /api/enrollments        → list pending enrollments
- POST /api/enrollments        → create enrollment (returns install one-liner)
- DELETE /api/enrollments/{id}
- GET  /api/enroll/{token}     → public: installer fetches details by token
- POST /api/enroll/{token}/complete → public: installer reports agent is up
- GET  /api/subscriptions      → list
- POST /api/subscriptions      → create
- PATCH /api/subscriptions/{id}
- DELETE /api/subscriptions/{id}
- GET  /sub/{token}            → public: base64-encoded vless list for clients
"""
from __future__ import annotations

import base64
import logging
import os
import secrets as _secrets
import uuid as uuidlib
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Optional

import pyotp
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit as audit_mod
from . import domain_provision
from . import payments as payments_mod
from . import sub_page
from . import tg_bots
from .agent_client import AgentClient, AgentError
from .auth import (
    SESSION_COOKIE,
    SESSION_MAX_AGE,
    current_user,
    hash_password,
    issue_session,
    verify_password,
)
from .database import get_db, init_db
from .models import (
    ApiToken,
    AuditLog,
    BotServerOverride,
    Client,
    DeviceFingerprint,
    EnrollmentToken,
    Order,
    Plan,
    Server,
    Setting,
    Subscription,
    TgBot,
    TgBotPlan,
    TgBotUser,
    User,
)
from .schemas import (
    ApiTokenCreateIn,
    ApiTokenOut,
    AuditLogOut,
    BotPlanCreateIn,
    BotPlanIn,
    BotPlanOut,
    BotServerOverrideIn,
    BotServerOverrideOut,
    BulkCreateClientsIn,
    BulkDeleteClientsIn,
    BulkExtendClientsIn,
    BulkResultOut,
    ChangePasswordIn,
    ClientCreateIn,
    ClientOut,
    ClientUpdateIn,
    DomainProvisionIn,
    EnrollmentCreateIn,
    EnrollmentDetailsOut,
    EnrollmentOut,
    LoginIn,
    NodeCompleteIn,
    NodeCompleteOut,
    OrderOut,
    PanelSettingsIn,
    PanelSettingsOut,
    PaymentSettingsIn,
    PaymentSettingsOut,
    PlanCreateIn,
    PlanIn,
    PlanOut,
    RebootIn,
    ServerCreateIn,
    ServerOut,
    ServerUpdateIn,
    SubscriptionCreateIn,
    SubscriptionOut,
    SubscriptionUpdateIn,
    TelegramConfigIn,
    TelegramConfigOut,
    TgBotBanIn,
    TgBotCreateIn,
    TgBotOut,
    TgBotUpdateIn,
    TgBotUserOut,
    TotpDisableIn,
    TotpSetupOut,
    TotpVerifyIn,
    XrayLogsOut,
)
from .xray_config import build_vless_link
from .xray_push import (
    WHITELIST_FRONT_MODE,
    delete_balancer_auth_clients,
    delete_bypass_auth_clients,
    is_balancer,
    is_service_client,
    is_whitelist_front,
    push_config as _shared_push_config,
    push_standalone_config,
    rebuild_balancer_configs,
    rebuild_whitelist_front_configs,
)


# ---------- app ----------
log = logging.getLogger(__name__)

app = FastAPI(title="xnPanel", version="1.1")

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"


def _render_shell(tpl: Path) -> str:
    """Return an HTML template with ?v=<mtime> appended to every local static
    asset include so upgrading the panel busts the browser cache for all
    users at once (no more 'кнопка не работает потому что старый JS')."""
    html = tpl.read_text()
    assets = ("styles.css", "app.js", "net-bg.js", "icons.js", "globe-bg.js")
    for name in assets:
        p = STATIC_DIR / name
        if not p.exists():
            continue
        ver = str(int(p.stat().st_mtime))
        for old in (f'"/static/{name}"', f"'/static/{name}'"):
            html = html.replace(old, old[0] + f"/static/{name}?v={ver}" + old[0])
    return html


@app.on_event("startup")
async def _startup() -> None:
    init_db()
    # Seed default subscription plans (30/90/365) on first boot so the
    # «💳 Оплата» panel section has something to show; no-op if any
    # plan already exists (admin owns prices after the first edit).
    from .database import SessionLocal
    with SessionLocal() as db:
        payments_mod.seed_default_plans(db)
    # Start the Telegram bot manager. Each enabled TgBot row becomes a
    # long-running asyncio task; the reconciler keeps that set in sync
    # with the DB, and the anti-fraud loop scans fingerprints periodically.
    await tg_bots.manager.start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await tg_bots.manager.stop()


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ---------- helpers ----------
def _server_to_dict(
    s: Server,
    *,
    online: bool = False,
    xray_version: str = "",
    xray_active: bool = False,
    client_count: int | None = None,
) -> dict:
    return {
        "id": s.id,
        "name": s.name,
        "display_name": getattr(s, "display_name", "") or "",
        "in_pool": bool(getattr(s, "in_pool", False)),
        "mode": (getattr(s, "mode", "") or "standalone"),
        "upstream_server_id": getattr(s, "upstream_server_id", None),
        "agent_url": s.agent_url,
        "public_host": s.public_host,
        "port": s.port,
        "sni": s.sni,
        "dest": s.dest,
        "public_key": s.public_key,
        "short_id": s.short_id,
        "created_at": s.created_at,
        "online": online,
        "xray_version": xray_version,
        "xray_active": xray_active,
        # Hide panel-managed balancer auth rows from the headline
        # client count so admins only see real users.
        "client_count": (
            client_count
            if client_count is not None
            else sum(1 for c in s.clients if not is_service_client(c))
        ),
    }


def _client_status(c: Client) -> str:
    if not bool(getattr(c, "enabled", True)):
        return "disabled"
    if c.is_expired():
        return "expired"
    if c.is_over_limit():
        return "limit"
    return "active"


def _server_label(
    server: Server,
    *,
    overrides: "Optional[dict[int, str]]" = None,
) -> str:
    """Human-readable label for a server in subscription entries.

    Lookup order:

    1. Per-bot override from ``overrides`` (when serving a TgBotUser sub).
    2. Server-wide ``display_name`` (panel admin override).
    3. Technical ``name``.
    """
    if overrides is not None:
        ov = (overrides.get(server.id, "") or "").strip()
        if ov:
            return ov
    return (getattr(server, "display_name", "") or "").strip() or server.name


# Prefix glyph applied to pool (auto-balance) entries. Picked because
# every modern font renders it and Hiddify / v2rayNG / Karing / Happ
# respect a common prefix as a grouping signal in the server list.
POOL_PREFIX = "⚡ "


def _subscription_label(
    server: Server,
    c: Client,
    *,
    overrides: "Optional[dict[int, str]]" = None,
) -> str:
    """Remark shown in ``vless://...#<label>`` and sing-box tags.

    Always leads with ``_server_label(server)`` so a rename flows
    through to every key on the next subscription refresh. Only
    appends the per-client label when it's genuinely custom —
    auto-generated labels (``<server-name>``, ``<server-name>-userN``,
    ``tg:<bot-name>``, or the client email itself) get hidden so the
    remark stays tidy after a server rename.

    Pool members get a ``POOL_PREFIX`` lightning-bolt prefix so clients
    that don't speak sing-box ``urltest`` (plain v2rayNG, generic
    vless importers) still see them as a visually grouped set and
    can run ``ping all → sort`` to pick the fastest manually.
    """
    base = _server_label(server, overrides=overrides)
    if bool(getattr(server, "in_pool", False)):
        base = f"{POOL_PREFIX}{base}"
    label = (c.label or "").strip()
    if not label:
        return base
    name = (server.name or "").strip()
    is_auto = (
        label == name
        or label == c.email
        or (name and label.startswith(f"{name}-"))
        or label.startswith("tg:")
        or label == "xray-reality"
    )
    if is_auto:
        return base
    return f"{base} — {label}"


def _client_to_dict(c: Client, server: Server) -> dict:
    link = build_vless_link(
        uuid=c.uuid,
        host=server.public_host,
        port=server.port,
        public_key=server.public_key,
        sni=server.sni,
        short_id=server.short_id,
        label=_subscription_label(server, c),
        flow=c.flow,
    )
    return {
        "id": c.id,
        "server_id": c.server_id,
        "uuid": c.uuid,
        "email": c.email,
        "label": c.label,
        "flow": c.flow,
        "total_up": c.total_up,
        "total_down": c.total_down,
        "created_at": c.created_at,
        "vless_link": link,
        "enabled": bool(getattr(c, "enabled", True)),
        "data_limit_bytes": getattr(c, "data_limit_bytes", None),
        "expires_at": getattr(c, "expires_at", None),
        "active": c.is_active(),
        "status": _client_status(c),
    }


def _short_id() -> str:
    return _secrets.token_hex(4)


def _push_config(server: Server, db: Session | None = None) -> None:
    """Thin wrapper: delegate to shared ``xray_push.push_config`` but
    keep the module-local name so older call sites don't need touching.
    """
    _shared_push_config(server, db)


def _fmt_stats(raw: Iterable[dict]) -> dict[str, dict[str, int]]:
    """Normalise the agent's stats into ``{email: {up, down}}``."""
    out: dict[str, dict[str, int]] = {}
    for item in raw:
        name = item.get("name", "")
        try:
            value = int(item.get("value", 0) or 0)
        except (TypeError, ValueError):
            value = 0
        # Xray stat names: user>>>EMAIL>>>traffic>>>uplink|downlink
        if name.startswith("user>>>") and ">>>traffic>>>" in name:
            email = name.split(">>>", 2)[1]
            direction = name.rsplit(">>>", 1)[-1]
            bucket = out.setdefault(email, {"up": 0, "down": 0})
            if direction == "uplink":
                bucket["up"] += value
            elif direction == "downlink":
                bucket["down"] += value
    return out


# ---------- auth ----------
@app.post("/api/auth/login")
def api_login(
    body: LoginIn,
    response: Response,
    db: Session = Depends(get_db),
) -> dict:
    user = db.scalar(select(User).where(User.username == body.username))
    if user is None or not verify_password(body.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid credentials")
    # 2FA: if the user has it enabled, require a valid code.
    if user.totp_secret:
        if not body.totp:
            # Distinct error code so the UI knows to prompt for the code
            # instead of flashing "invalid credentials".
            raise HTTPException(status_code=401, detail="totp required")
        if not pyotp.TOTP(user.totp_secret).verify(body.totp.strip(), valid_window=1):
            raise HTTPException(status_code=401, detail="invalid totp code")
    token = issue_session(user.id)
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=SESSION_MAX_AGE,
        httponly=True,
        samesite="lax",
        secure=False,  # panel usually behind plain HTTP on LAN / SSH tunnel
    )
    return {"ok": True, "username": user.username}


@app.post("/api/auth/logout")
def api_logout(response: Response) -> dict:
    response.delete_cookie(SESSION_COOKIE)
    return {"ok": True}


@app.get("/api/auth/me")
def api_me(user: User = Depends(current_user)) -> dict:
    return {
        "username": user.username,
        "totp_enabled": bool(user.totp_secret),
    }


# ---------- 2FA ----------
@app.post("/api/auth/2fa/setup", response_model=TotpSetupOut)
def api_totp_setup(
    user: User = Depends(current_user),
) -> dict:
    """Generate a fresh TOTP secret + provisioning URI for the user to scan
    into their authenticator app. The secret isn't persisted yet — the user
    must call /2fa/enable with a valid code first."""
    if user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username, issuer_name="xnPanel"
    )
    return {"secret": secret, "provisioning_uri": uri}


@app.post("/api/auth/2fa/enable")
def api_totp_enable(
    body: TotpVerifyIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is already enabled")
    if not pyotp.TOTP(body.secret).verify(body.code.strip(), valid_window=1):
        raise HTTPException(status_code=400, detail="invalid code")
    user.totp_secret = body.secret
    audit_mod.record(db, user=user, action="auth.2fa_enable")
    db.commit()
    return {"ok": True}


@app.post("/api/auth/2fa/disable")
def api_totp_disable(
    body: TotpDisableIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA is not enabled")
    if not pyotp.TOTP(user.totp_secret).verify(body.code.strip(), valid_window=1):
        raise HTTPException(status_code=400, detail="invalid code")
    user.totp_secret = None
    audit_mod.record(db, user=user, action="auth.2fa_disable")
    db.commit()
    return {"ok": True}


@app.post("/api/auth/password")
def api_change_password(
    body: ChangePasswordIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="current password is wrong")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    return {"ok": True}


# ---------- servers ----------
@app.get("/api/servers", response_model=list[ServerOut])
def api_list_servers(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(select(Server).order_by(Server.id)).all()
    out: list[dict] = []
    for s in rows:
        online = False
        xray_version = ""
        xray_active = False
        try:
            h = AgentClient(s.agent_url, s.agent_token).health()
            online = True
            xray_version = h.get("xray_version", "")
            xray_active = bool(h.get("xray_active", False))
        except Exception:
            online = False
        out.append(
            _server_to_dict(
                s,
                online=online,
                xray_version=xray_version,
                xray_active=xray_active,
            )
        )
    return out


@app.post("/api/servers", response_model=ServerOut, status_code=201)
def api_create_server(
    body: ServerCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if db.scalar(select(Server).where(Server.name == body.name)):
        raise HTTPException(status_code=400, detail="a server with this name already exists")

    # Balancer / whitelist-front nodes must be installed via enrollment —
    # the agent needs Reality keys + a working inbound + a synchronised
    # upstream view before the server row is usable. Refuse to let the
    # manual form create one under the default ``standalone``
    # assumption.
    if (body.mode or "standalone") != "standalone":
        raise HTTPException(
            status_code=400,
            detail=(
                "router-mode servers (balancer / whitelist-front) must be "
                "added via the dedicated enrollment buttons. The manual "
                "form only supports mode=standalone."
            ),
        )

    agent = AgentClient(body.agent_url, body.agent_token)
    # Sanity check — fail fast if the agent isn't reachable.
    try:
        agent.health()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"could not reach agent: {e}") from e

    private_key = body.private_key or ""
    public_key = body.public_key or ""
    if not private_key or not public_key:
        try:
            kp = agent.gen_keypair()
            private_key = kp["private_key"]
            public_key = kp["public_key"]
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"keypair generation failed: {e}") from e

    server = Server(
        name=body.name,
        display_name=(body.display_name or "").strip(),
        in_pool=bool(body.in_pool),
        agent_url=body.agent_url.rstrip("/"),
        agent_token=body.agent_token,
        public_host=body.public_host,
        port=body.port,
        sni=body.sni,
        dest=body.dest,
        private_key=private_key,
        public_key=public_key,
        short_id=body.short_id or _short_id(),
    )
    db.add(server)
    db.commit()
    db.refresh(server)

    # Seed with a first client so the user gets a working vless link immediately.
    first = Client(
        server_id=server.id,
        uuid=str(uuidlib.uuid4()),
        email=f"{server.name}-user1",
        label=f"{server.name}",
        flow="xtls-rprx-vision",
    )
    db.add(first)
    db.commit()
    db.refresh(server)

    try:
        _push_config(server, db)
    except AgentError as e:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

    audit_mod.record(
        db, user=user, action="server.create",
        resource_type="server", resource_id=server.id,
        details=f"{server.name} ({server.public_host}:{server.port})",
    )
    db.commit()
    return _server_to_dict(server, online=True)


@app.get("/api/servers/{server_id}", response_model=ServerOut)
def api_get_server(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    online = False
    xray_version = ""
    xray_active = False
    try:
        h = AgentClient(s.agent_url, s.agent_token).health()
        online = True
        xray_version = h.get("xray_version", "")
        xray_active = bool(h.get("xray_active", False))
    except Exception:
        pass
    return _server_to_dict(
        s,
        online=online,
        xray_version=xray_version,
        xray_active=xray_active,
    )


@app.patch("/api/servers/{server_id}", response_model=ServerOut)
def api_update_server(
    server_id: int,
    body: ServerUpdateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    # A balancer is never its own upstream — silently ignore an attempt
    # to flip ``in_pool`` on one instead of 400-ing so older UI builds
    # that always send the full payload don't trip the error.
    if body.in_pool is True and is_balancer(s):
        body.in_pool = None
    # Validate / normalise an upstream re-point on a whitelist-front:
    # only meaningful when the row is a front, and the target must be
    # a standalone (no chain-of-chain).
    if body.upstream_server_id is not None:
        if not is_whitelist_front(s):
            raise HTTPException(
                status_code=400,
                detail="upstream_server_id is only valid on whitelist-front nodes",
            )
        # Treat 0 / negative as "unlink".
        target = int(body.upstream_server_id) or 0
        if target <= 0:
            body.upstream_server_id = None  # type: ignore[assignment]
        else:
            up = db.get(Server, target)
            if up is None:
                raise HTTPException(
                    status_code=400,
                    detail=f"upstream server {target} not found",
                )
            if up.id == s.id:
                raise HTTPException(
                    status_code=400,
                    detail="a whitelist-front can't point at itself",
                )
            if (getattr(up, "mode", "") or "standalone") != "standalone":
                raise HTTPException(
                    status_code=400,
                    detail=(
                        "upstream must be a standalone node — "
                        f"server {up.id} is mode={up.mode!r}"
                    ),
                )
            body.upstream_server_id = up.id  # type: ignore[assignment]
    dirty_xray = False
    upstream_changed = False
    old_upstream_id: int | None = None
    changed: list[str] = []
    for field in (
        "name", "display_name", "in_pool", "agent_url", "agent_token",
        "public_host", "port", "sni", "dest",
    ):
        v = getattr(body, field, None)
        if v is None:
            continue
        old = getattr(s, field, None)
        if v == old:
            continue
        if field in {"port", "sni", "dest"}:
            dirty_xray = True
        setattr(s, field, v)
        # Redact the token in the audit trail; log only that it changed.
        if field == "agent_token":
            changed.append("agent_token=<rotated>")
        else:
            changed.append(f"{field}={old!r}→{v!r}")
    # Handle upstream_server_id separately: ``None`` is a meaningful
    # value (unlink), so we can't bail on ``v is None`` like the loop
    # above does. Only act when the field was explicitly part of the
    # request payload (model_fields_set tracks that in pydantic v2).
    if (
        is_whitelist_front(s)
        and "upstream_server_id" in body.model_fields_set
    ):
        new_up = body.upstream_server_id
        old_up = getattr(s, "upstream_server_id", None)
        if new_up != old_up:
            old_upstream_id = old_up
            s.upstream_server_id = new_up
            dirty_xray = True
            upstream_changed = True
            changed.append(f"upstream_server_id={old_up!r}→{new_up!r}")
    if changed:
        audit_mod.record(
            db, user=user, action="server.update",
            resource_type="server", resource_id=s.id,
            details=", ".join(changed),
        )
    db.commit()
    if dirty_xray:
        try:
            _push_config(s, db)
        except AgentError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    # If ``in_pool`` just flipped, every balancer's outbound list needs
    # to be rebuilt. This also re-pushes the *new* pool member's own
    # config so the panel-managed ``__balancer__-<id>`` auth client
    # gets registered on its xray before the balancer dials it.
    if any(c.startswith("in_pool=") for c in changed):
        rebuild_balancer_configs(db)
    # When a whitelist-front gets re-pointed, the old upstream still
    # has a stale ``__bypass__-<front_id>`` auth client. Scrub it +
    # re-push the old upstream so xray drops that UUID.
    if upstream_changed and old_upstream_id is not None:
        try:
            old_up = db.get(Server, old_upstream_id)
            email = f"__bypass__-{s.id}"
            stale = db.scalar(
                select(Client).where(
                    Client.server_id == old_upstream_id,
                    Client.email == email,
                )
            )
            if stale is not None:
                db.delete(stale)
                db.commit()
            if old_up is not None:
                push_standalone_config(old_up)
        except AgentError as exc:
            log.warning(
                "post-repoint cleanup on upstream %d failed: %s",
                old_upstream_id, exc,
            )
    return _server_to_dict(s)


@app.delete("/api/servers/{server_id}")
def api_delete_server(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    name = s.name
    sid = s.id
    was_balancer = is_balancer(s)
    was_whitelist_front = is_whitelist_front(s)
    was_in_pool = bool(getattr(s, "in_pool", False))
    # Snapshot which whitelist-fronts depended on this row BEFORE
    # delete cascade nulls their FK — we'll re-push those fronts after
    # delete so they fall back to direct egress instead of dialling a
    # dead upstream.
    dependent_front_ids: list[int] = list(
        db.scalars(
            select(Server.id).where(Server.upstream_server_id == sid)
        ).all()
    )
    db.delete(s)
    db.commit()
    # Keep the cross-node auth graph in sync with the delete:
    # * if this was a balancer, scrub its ``__balancer__-<id>`` auth
    #   rows from every upstream (and re-push those upstreams so xray
    #   drops the now-unused credential);
    # * if this was a whitelist-front, scrub its ``__bypass__-<id>``
    #   auth rows from the foreign upstream the same way;
    # * if this was a pool member, every balancer needs its outbound
    #   list rebuilt — otherwise it would keep trying to dial a dead
    #   upstream;
    # * if this was the foreign exit of any whitelist-front, those
    #   fronts need a fresh push so they degrade to direct egress.
    if was_balancer:
        affected = delete_balancer_auth_clients(db, sid)
        for up in affected:
            try:
                push_standalone_config(up)
            except AgentError as exc:
                log.warning(
                    "post-delete push to upstream %d failed: %s", up.id, exc,
                )
    if was_whitelist_front:
        affected_fronts = delete_bypass_auth_clients(db, sid)
        for up in affected_fronts:
            try:
                push_standalone_config(up)
            except AgentError as exc:
                log.warning(
                    "post-delete push to bypass upstream %d failed: %s",
                    up.id, exc,
                )
    if was_in_pool or was_balancer:
        rebuild_balancer_configs(db)
    if dependent_front_ids:
        rebuild_whitelist_front_configs(db)
    audit_mod.record(
        db, user=user, action="server.delete",
        resource_type="server", resource_id=sid, details=name,
    )
    db.commit()
    return {"ok": True}


@app.get("/api/servers/{server_id}/stats")
def api_server_stats(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    agent = AgentClient(s.agent_url, s.agent_token)
    sysinfo: dict | None = None
    traffic: dict[str, dict[str, int]] = {}
    online = False
    try:
        sysinfo = agent.sysinfo()
        online = True
    except Exception:
        sysinfo = None
    try:
        traffic = _fmt_stats(agent.stats(reset=False))
    except Exception:
        traffic = {}

    # Merge traffic into client totals (cumulative — we do not reset here to keep
    # totals accurate on panel restart; full reset handled by a separate endpoint
    # if ever needed). While iterating, track whether any client's active status
    # flipped from "active" to "inactive" so we can re-push the xray config and
    # actually cut off over-limit / expired users.
    needs_push = False
    flipped_clients: list[tuple[Client, str]] = []
    clients_out: list[dict] = []
    for c in s.clients:
        was_active = c.is_active()
        t = traffic.get(c.email)
        if t:
            # xray stats are reset only when we ask; since we don't reset here,
            # we take the current max(live, stored).
            c.total_up = max(c.total_up, t["up"])
            c.total_down = max(c.total_down, t["down"])
        if was_active and not c.is_active():
            needs_push = True
            flipped_clients.append((c, _client_status(c)))
        clients_out.append(_client_to_dict(c, s))
    db.commit()

    for c, new_status in flipped_clients:
        audit_mod.record(
            db, user=None, action="client.disabled_automatically",
            resource_type="client", resource_id=c.id,
            details=f"{c.email} @ {s.name} — reason={new_status}",
        )
    if flipped_clients:
        db.commit()

    if needs_push and online:
        try:
            _push_config(s, db)
        except Exception:
            # Best-effort — we already committed the stats; a later stats call
            # or manual restart will sync xray.
            pass

    return {
        "online": online,
        "sysinfo": sysinfo,
        "clients": clients_out,
    }


# ---------- clients ----------
@app.get("/api/servers/{server_id}/clients", response_model=list[ClientOut])
def api_list_clients(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    # Hide panel-managed balancer auth rows — they're not real users,
    # they only exist so a balancer can dial this upstream.
    return [_client_to_dict(c, s) for c in s.clients if not is_service_client(c)]


@app.post("/api/servers/{server_id}/clients", response_model=ClientOut, status_code=201)
def api_create_client(
    server_id: int,
    body: ClientCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if db.scalar(
        select(func.count())
        .select_from(Client)
        .where(Client.server_id == s.id, Client.email == body.email)
    ):
        raise HTTPException(status_code=400, detail="email already exists on this server")

    client = Client(
        server_id=s.id,
        uuid=str(uuidlib.uuid4()),
        email=body.email,
        label=body.label or body.email,
        flow=body.flow or "xtls-rprx-vision",
        data_limit_bytes=body.data_limit_bytes,
        expires_at=body.expires_at,
    )
    db.add(client)
    db.commit()
    db.refresh(s)

    try:
        _push_config(s, db)
    except AgentError as e:
        db.delete(client)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

    audit_mod.record(
        db,
        user=user,
        action="client.create",
        resource_type="client",
        resource_id=client.id,
        details=f"{body.email} @ {s.name}",
    )
    db.commit()
    return _client_to_dict(client, s)


@app.patch("/api/servers/{server_id}/clients/{client_id}", response_model=ClientOut)
def api_update_client(
    server_id: int,
    client_id: int,
    body: ClientUpdateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    c = db.get(Client, client_id)
    if c is None or c.server_id != s.id:
        raise HTTPException(status_code=404, detail="client not found")

    fields = body.model_dump(exclude_unset=True)
    if "label" in fields and fields["label"] is not None:
        c.label = fields["label"]
    if "enabled" in fields and fields["enabled"] is not None:
        c.enabled = bool(fields["enabled"])
    if "data_limit_bytes" in fields:
        c.data_limit_bytes = fields["data_limit_bytes"]
    if "expires_at" in fields:
        c.expires_at = fields["expires_at"]
    db.commit()
    db.refresh(s)

    # Re-push config — an active/inactive flip should reach xray immediately.
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return _client_to_dict(c, s)


@app.post("/api/servers/{server_id}/clients/{client_id}/reset-usage", response_model=ClientOut)
def api_reset_client_usage(
    server_id: int,
    client_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Zero the client's total_up/total_down counters (re-opens over-limit keys)."""
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    c = db.get(Client, client_id)
    if c is None or c.server_id != s.id:
        raise HTTPException(status_code=404, detail="client not found")
    c.total_up = 0
    c.total_down = 0
    db.commit()
    db.refresh(s)
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    return _client_to_dict(c, s)


@app.delete("/api/servers/{server_id}/clients/{client_id}")
def api_delete_client(
    server_id: int,
    client_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    c = db.get(Client, client_id)
    if c is None or c.server_id != s.id:
        raise HTTPException(status_code=404, detail="client not found")
    deleted_email = c.email
    deleted_id = c.id
    db.delete(c)
    db.commit()
    db.refresh(s)

    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    audit_mod.record(
        db,
        user=user,
        action="client.delete",
        resource_type="client",
        resource_id=deleted_id,
        details=f"{deleted_email} @ {s.name}",
    )
    db.commit()
    return {"ok": True}


# ---------- bulk client ops ----------
@app.post(
    "/api/servers/{server_id}/clients/bulk",
    response_model=list[ClientOut],
    status_code=201,
)
def api_bulk_create_clients(
    server_id: int,
    body: BulkCreateClientsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    """Create N clients named ``{prefix}-1``..``{prefix}-N`` on one server.

    Skips emails that already exist — the admin can safely re-run with the
    same prefix after a partial failure. Pushes config exactly once.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")

    existing = {
        e for (e,) in db.execute(
            select(Client.email).where(Client.server_id == s.id)
        ).all()
    }
    created: list[Client] = []
    for i in range(1, body.count + 1):
        email = f"{body.email_prefix}-{i}"
        if email in existing:
            continue
        c = Client(
            server_id=s.id,
            uuid=str(uuidlib.uuid4()),
            email=email,
            label=body.label or email,
            flow=body.flow or "xtls-rprx-vision",
            data_limit_bytes=body.data_limit_bytes,
            expires_at=body.expires_at,
        )
        db.add(c)
        created.append(c)
    db.commit()
    db.refresh(s)

    try:
        _push_config(s, db)
    except AgentError as e:
        # Rollback the created rows so we don't get stuck with DB rows the
        # node doesn't know about.
        for c in created:
            db.delete(c)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

    audit_mod.record(
        db,
        user=user,
        action="client.bulk_create",
        resource_type="server",
        resource_id=s.id,
        details=f"prefix={body.email_prefix} count={len(created)} @ {s.name}",
    )
    db.commit()
    return [_client_to_dict(c, s) for c in created]


@app.post(
    "/api/servers/{server_id}/clients/bulk-extend",
    response_model=BulkResultOut,
)
def api_bulk_extend_clients(
    server_id: int,
    body: BulkExtendClientsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    rows = db.scalars(
        select(Client).where(Client.server_id == s.id, Client.id.in_(body.client_ids))
    ).all()
    now = datetime.utcnow()
    for c in rows:
        base = c.expires_at if c.expires_at and c.expires_at > now else now
        c.expires_at = base + timedelta(days=body.extra_days)
    db.commit()
    db.refresh(s)
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    audit_mod.record(
        db,
        user=user,
        action="client.bulk_extend",
        resource_type="server",
        resource_id=s.id,
        details=f"+{body.extra_days}d × {len(rows)} @ {s.name}",
    )
    db.commit()
    return {"affected": len(rows)}


@app.post(
    "/api/servers/{server_id}/clients/bulk-delete",
    response_model=BulkResultOut,
)
def api_bulk_delete_clients(
    server_id: int,
    body: BulkDeleteClientsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    rows = db.scalars(
        select(Client).where(Client.server_id == s.id, Client.id.in_(body.client_ids))
    ).all()
    affected = len(rows)
    for c in rows:
        db.delete(c)
    db.commit()
    db.refresh(s)
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    audit_mod.record(
        db,
        user=user,
        action="client.bulk_delete",
        resource_type="server",
        resource_id=s.id,
        details=f"{affected} × @ {s.name}",
    )
    db.commit()
    return {"affected": affected}


# ---------- server management ----------
_ALLOWED_XRAY_ACTIONS = {"restart", "start", "stop"}


@app.post("/api/servers/{server_id}/xray/{action}")
def api_xray_action(
    server_id: int,
    action: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if action not in _ALLOWED_XRAY_ACTIONS:
        raise HTTPException(status_code=400, detail=f"unknown action: {action}")
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        return AgentClient(s.agent_url, s.agent_token).xray_action(action)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e


@app.get("/api/servers/{server_id}/xray/logs", response_model=XrayLogsOut)
def api_xray_logs(
    server_id: int,
    lines: int = 200,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        return {"lines": AgentClient(s.agent_url, s.agent_token).xray_logs(lines=lines)}
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e


@app.post("/api/servers/{server_id}/reboot")
def api_server_reboot(
    server_id: int,
    body: RebootIn | None = None,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    delay = 3 if body is None else max(0, int(body.delay_seconds))
    try:
        result = AgentClient(s.agent_url, s.agent_token).reboot(delay_seconds=delay)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e
    audit_mod.record(
        db, user=user, action="server.reboot",
        resource_type="server", resource_id=s.id, details=f"{s.name} delay={delay}s",
    )
    db.commit()
    return result


@app.post("/api/servers/{server_id}/rotate-keys", response_model=ServerOut)
def api_rotate_keys(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Regenerate Reality x25519 keypair + shortId via the agent, then push.

    Existing clients keep their UUIDs but get a brand new pbk/sid bundle in
    their vless:// links — they must re-import the new link to connect again.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    agent = AgentClient(s.agent_url, s.agent_token)
    try:
        kp = agent.gen_keypair()
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"keypair generation failed: {e}") from e
    s.private_key = kp["private_key"]
    s.public_key = kp["public_key"]
    s.short_id = _short_id()
    db.commit()
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    # If this is in the auto-balance pool or a foreign exit for any
    # whitelist-front, every dependent router needs a re-push too —
    # otherwise they'd keep dialling the upstream with the OLD pubkey.
    if bool(getattr(s, "in_pool", False)):
        rebuild_balancer_configs(db)
    rebuild_whitelist_front_configs(db, only_upstream_id=s.id)
    return _server_to_dict(s, online=True)


# ---------- enrollments ----------
def _panel_base_url(request: Request) -> str:
    """Return the panel's public base URL for building install one-liners.

    Priority: ``PANEL_PUBLIC_URL`` env > the current request's scheme+host.
    """
    env = os.environ.get("PANEL_PUBLIC_URL", "").strip().rstrip("/")
    if env:
        return env
    # Trust Forwarded-* headers first, then fall back to request URL.
    fwd_proto = request.headers.get("x-forwarded-proto", "").strip()
    fwd_host = request.headers.get("x-forwarded-host", "").strip()
    host = fwd_host or request.headers.get("host", "").strip() or request.url.netloc
    scheme = fwd_proto or request.url.scheme or "http"
    return f"{scheme}://{host}"


def _install_repo_url() -> str:
    return os.environ.get(
        "PANEL_INSTALLER_URL",
        "https://raw.githubusercontent.com/sacoq/xray-reality-installer/main/install.sh",
    )


def _build_install_command(request: Request, token: str, domain: str = "") -> str:
    panel = _panel_base_url(request)
    installer = _install_repo_url()
    domain_arg = f' --domain "{domain}"' if domain else ""
    return (
        f'curl -fsSL {installer} | sudo bash -s -- '
        f'--node-enroll --panel-url "{panel}" --enroll-token "{token}"'
        f'{domain_arg} --yes'
    )


def _enrollment_to_dict(e: EnrollmentToken, request: Request) -> dict:
    return {
        "id": e.id,
        "token": e.token,
        "name": e.name,
        "display_name": getattr(e, "display_name", "") or "",
        "in_pool": bool(getattr(e, "in_pool", False)),
        "mode": (getattr(e, "mode", "") or "standalone"),
        "upstream_server_id": getattr(e, "upstream_server_id", None),
        "public_host": e.public_host,
        "port": e.port,
        "sni": e.sni,
        "dest": e.dest,
        "agent_port": e.agent_port,
        "agent_token": e.agent_token,
        "used_at": e.used_at,
        "server_id": e.server_id,
        "created_at": e.created_at,
        "install_command": _build_install_command(request, e.token, e.public_host),
    }


@app.get("/api/enrollments", response_model=list[EnrollmentOut])
def api_list_enrollments(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(select(EnrollmentToken).order_by(EnrollmentToken.id.desc())).all()
    return [_enrollment_to_dict(e, request) for e in rows]


@app.post("/api/enrollments", response_model=EnrollmentOut, status_code=201)
def api_create_enrollment(
    body: EnrollmentCreateIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    # Reject names that already exist as servers — the node will be registered
    # under this name, so it must be free.
    if db.scalar(select(Server).where(Server.name == body.name)):
        raise HTTPException(status_code=400, detail="a server with this name already exists")
    if db.scalar(
        select(EnrollmentToken).where(
            EnrollmentToken.name == body.name, EnrollmentToken.used_at.is_(None)
        )
    ):
        raise HTTPException(
            status_code=400, detail="a pending enrollment with this name already exists"
        )
    mode = (body.mode or "standalone").strip() or "standalone"
    if mode not in ("standalone", "balancer", WHITELIST_FRONT_MODE):
        raise HTTPException(
            status_code=400,
            detail=(
                f"unknown mode: {mode!r} "
                "(expected 'standalone', 'balancer' or 'whitelist-front')"
            ),
        )
    # whitelist-front nodes need a foreign exit picked up-front so the
    # very first config push wires the chain correctly. The upstream
    # MUST be a standalone node — chaining a chain would loop.
    upstream_id = body.upstream_server_id or None
    if mode == WHITELIST_FRONT_MODE:
        if not upstream_id:
            raise HTTPException(
                status_code=400,
                detail=(
                    "whitelist-front nodes require upstream_server_id "
                    "(the foreign exit Server.id this front will dial)"
                ),
            )
        upstream = db.get(Server, upstream_id)
        if upstream is None:
            raise HTTPException(
                status_code=400,
                detail=f"upstream server {upstream_id} not found",
            )
        if (getattr(upstream, "mode", "") or "standalone") != "standalone":
            raise HTTPException(
                status_code=400,
                detail=(
                    "upstream must be a standalone node — "
                    f"server {upstream.id} is mode={upstream.mode!r}"
                ),
            )
    else:
        # Carrying an upstream id on a non-front enrollment would just
        # be confusing; drop it silently so older UI builds don't trip.
        upstream_id = None
    # Balancer / whitelist-front nodes are routers, not pool members.
    # Guard against the UI accidentally flagging them as in-pool.
    in_pool = (
        bool(body.in_pool) and mode != "balancer" and mode != WHITELIST_FRONT_MODE
    )
    enrollment = EnrollmentToken(
        token=_secrets.token_urlsafe(24),
        name=body.name,
        display_name=(body.display_name or "").strip(),
        in_pool=in_pool,
        mode=mode,
        upstream_server_id=upstream_id,
        public_host=body.public_host or "",
        port=body.port,
        sni=body.sni,
        dest=body.dest,
        agent_port=body.agent_port,
        agent_token=_secrets.token_hex(24),
    )
    db.add(enrollment)
    db.commit()
    db.refresh(enrollment)
    return _enrollment_to_dict(enrollment, request)


@app.delete("/api/enrollments/{enrollment_id}")
def api_delete_enrollment(
    enrollment_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    e = db.get(EnrollmentToken, enrollment_id)
    if e is None:
        raise HTTPException(status_code=404, detail="enrollment not found")
    db.delete(e)
    db.commit()
    return {"ok": True}


@app.get("/api/enroll/{token}", response_model=EnrollmentDetailsOut)
def api_enroll_details(token: str, db: Session = Depends(get_db)) -> dict:
    """Public endpoint hit by the installer on a fresh node to fetch the
    intended agent_token + xray inbound settings for this enrollment."""
    e = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token == token))
    if e is None:
        raise HTTPException(status_code=404, detail="unknown enrollment token")
    if e.used_at is not None:
        raise HTTPException(status_code=400, detail="enrollment already used")
    return {
        "name": e.name,
        "port": e.port,
        "sni": e.sni,
        "dest": e.dest,
        "agent_port": e.agent_port,
        "agent_token": e.agent_token,
        "public_host": e.public_host,
    }


@app.post("/api/enroll/{token}/complete", response_model=NodeCompleteOut)
def api_enroll_complete(
    token: str,
    body: NodeCompleteIn,
    db: Session = Depends(get_db),
) -> dict:
    """Public endpoint hit by the installer once the agent is live.

    The panel calls the agent (authenticated with the enrollment's agent_token),
    generates x25519 keys, creates the Server row + a first VLESS client and
    pushes the initial config. Enrollment is marked used and cannot be reused.
    """
    e = db.scalar(select(EnrollmentToken).where(EnrollmentToken.token == token))
    if e is None:
        raise HTTPException(status_code=404, detail="unknown enrollment token")
    if e.used_at is not None:
        raise HTTPException(status_code=400, detail="enrollment already used")

    agent_url = body.agent_url.rstrip("/")
    public_host = (body.public_host or e.public_host or "").strip()
    if not public_host:
        raise HTTPException(
            status_code=400,
            detail="public_host is required (set it when creating the enrollment or pass --domain)",
        )
    if db.scalar(select(Server).where(Server.name == e.name)):
        raise HTTPException(status_code=400, detail=f"server '{e.name}' already exists")

    agent = AgentClient(agent_url, e.agent_token)
    try:
        agent.health()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"panel could not reach agent at {agent_url}: {exc}"
        ) from exc
    try:
        kp = agent.gen_keypair()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=f"keypair generation failed: {exc}") from exc

    # Installer may override sni/dest/port if it auto-probed a better SNI on
    # the node than what the admin pre-filled on the enrollment. This is the
    # common case (default panel SNI is rutube.ru which is often unreachable
    # from EU DCs).
    eff_sni = (body.sni or e.sni).strip()
    eff_dest = (body.dest or e.dest).strip()
    eff_port = int(body.port) if body.port else e.port
    enrolled_mode = (getattr(e, "mode", "") or "standalone") or "standalone"
    enrolled_in_pool = (
        bool(getattr(e, "in_pool", False))
        and enrolled_mode not in ("balancer", WHITELIST_FRONT_MODE)
    )
    enrolled_upstream_id = getattr(e, "upstream_server_id", None) or None
    if enrolled_mode == WHITELIST_FRONT_MODE and enrolled_upstream_id is not None:
        # Re-validate at completion time — admin may have deleted the
        # foreign exit between creating the enrollment and the installer
        # actually running. We don't 400 in that case (the installer is
        # already up and we don't want to leak a half-installed node);
        # we just degrade to "no upstream" so the front comes up routing
        # direct, and surface that in the UI.
        up = db.get(Server, enrolled_upstream_id)
        if up is None or (getattr(up, "mode", "") or "standalone") != "standalone":
            log.warning(
                "enrollment %d: upstream server %s no longer usable, "
                "leaving whitelist-front unconfigured",
                e.id, enrolled_upstream_id,
            )
            enrolled_upstream_id = None
    server = Server(
        name=e.name,
        display_name=(getattr(e, "display_name", "") or "").strip(),
        in_pool=enrolled_in_pool,
        mode=enrolled_mode,
        upstream_server_id=enrolled_upstream_id,
        agent_url=agent_url,
        agent_token=e.agent_token,
        public_host=public_host,
        port=eff_port,
        sni=eff_sni,
        dest=eff_dest,
        private_key=kp["private_key"],
        public_key=kp["public_key"],
        short_id=_short_id(),
    )
    db.add(server)
    db.commit()
    db.refresh(server)

    # Balancer nodes don't seed a first user client — they exist to
    # route real users installed on the standalone pool members. An
    # admin creates end-user keys later via /api/clients just like on
    # any other server (and those keys land on the balancer's own
    # inbound, which is how users connect to the balancer).
    #
    # whitelist-front nodes DO seed a first client: users connect their
    # vless:// link directly to the front (the chain is invisible to
    # them), so the front needs at least one user key out of the box.
    if enrolled_mode in ("standalone", WHITELIST_FRONT_MODE):
        first = Client(
            server_id=server.id,
            uuid=str(uuidlib.uuid4()),
            email=f"{server.name}-user1",
            label=server.name,
            flow="xtls-rprx-vision",
        )
        db.add(first)
        db.commit()
        db.refresh(server)

    try:
        _push_config(server, db)
    except AgentError as exc:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # A fresh pool member means every existing balancer needs its
    # outbound list rebuilt so it starts probing this upstream.
    if enrolled_in_pool:
        rebuild_balancer_configs(db)

    e.used_at = datetime.utcnow()
    e.server_id = server.id
    db.commit()
    return {"ok": True, "server_id": server.id, "server_name": server.name}


# ---------- subscriptions ----------
def _subscription_clients(s: Subscription, db: Session) -> list[Client]:
    """Real end-user keys under this subscription.

    Panel-managed balancer auth rows (``__balancer__-<id>`` clients on
    pool upstreams) are hidden — they exist only so a balancer node
    can dial its upstreams, they should never appear in a user-facing
    subscription.
    """
    if s.include_all:
        rows = db.scalars(select(Client).order_by(Client.id)).all()
    else:
        rows = list(s.clients)
    return [c for c in rows if not is_service_client(c)]


def _subscription_to_dict(s: Subscription, request: Request, db: Session) -> dict:
    clients = _subscription_clients(s, db)
    base = _panel_base_url(request)
    return {
        "id": s.id,
        "name": s.name,
        "token": s.token,
        "include_all": s.include_all,
        "client_ids": [c.id for c in clients],
        "server_ids": sorted({c.server_id for c in clients}),
        "item_count": len(clients),
        "url": f"{base}/sub/{s.token}",
        "profile_title": getattr(s, "profile_title", "") or "",
        "support_url": getattr(s, "support_url", "") or "",
        "announce": getattr(s, "announce", "") or "",
        "provider_id": getattr(s, "provider_id", "") or "",
        "routing": getattr(s, "routing", "") or "",
        "update_interval_hours": int(getattr(s, "update_interval_hours", 24) or 24),
        "created_at": s.created_at,
    }


@app.get("/api/subscriptions", response_model=list[SubscriptionOut])
def api_list_subscriptions(
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(select(Subscription).order_by(Subscription.id)).all()
    return [_subscription_to_dict(s, request, db) for s in rows]


@app.post("/api/subscriptions", response_model=SubscriptionOut, status_code=201)
def api_create_subscription(
    body: SubscriptionCreateIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if db.scalar(select(Subscription).where(Subscription.name == body.name)):
        raise HTTPException(
            status_code=400, detail="a subscription with this name already exists"
        )
    sub = Subscription(
        name=body.name,
        token=_secrets.token_urlsafe(18),
        include_all=bool(body.include_all),
        profile_title=(body.profile_title or "").strip(),
        support_url=(body.support_url or "").strip(),
        announce=(body.announce or "").strip(),
        provider_id=(body.provider_id or "").strip(),
        routing=(body.routing or "").strip(),
        update_interval_hours=int(body.update_interval_hours or 24),
    )
    if not body.include_all and body.client_ids:
        picked = list(
            db.scalars(select(Client).where(Client.id.in_(body.client_ids))).all()
        )
        sub.clients = picked
    db.add(sub)
    db.commit()
    db.refresh(sub)
    return _subscription_to_dict(sub, request, db)


@app.patch("/api/subscriptions/{sub_id}", response_model=SubscriptionOut)
def api_update_subscription(
    sub_id: int,
    body: SubscriptionUpdateIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    sub = db.get(Subscription, sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    if body.name is not None:
        sub.name = body.name
    if body.include_all is not None:
        sub.include_all = bool(body.include_all)
    for field in (
        "profile_title", "support_url", "announce", "provider_id", "routing",
    ):
        v = getattr(body, field)
        if v is not None:
            setattr(sub, field, v.strip() if isinstance(v, str) else v)
    if body.update_interval_hours is not None:
        sub.update_interval_hours = int(body.update_interval_hours)
    if body.client_ids is not None:
        picked = list(
            db.scalars(select(Client).where(Client.id.in_(body.client_ids))).all()
        )
        sub.clients = picked
    db.commit()
    db.refresh(sub)
    return _subscription_to_dict(sub, request, db)


@app.delete("/api/subscriptions/{sub_id}")
def api_delete_subscription(
    sub_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    sub = db.get(Subscription, sub_id)
    if sub is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    db.delete(sub)
    db.commit()
    return {"ok": True}


_SUBSCRIPTION_FORMATS = {"", "v2ray", "vless", "singbox", "sing-box", "clash", "json"}


def _subscription_entries(sub: Subscription, db: Session) -> list[tuple[Client, Server]]:
    """Return active (client, server) pairs for a subscription, skipping
    inactive (disabled / expired / over-limit) clients and orphan rows."""
    out: list[tuple[Client, Server]] = []
    for c in _subscription_clients(sub, db):
        if not c.is_active():
            continue
        server = c.server
        if server is None:
            continue
        out.append((c, server))
    return out


def _compute_userinfo(entries: list[tuple[Client, Server]]) -> str:
    """Build the ``Subscription-Userinfo`` header value.

    Aggregates ``upload``/``download``/``total``/``expire`` across every
    active key in the subscription:

    * ``upload`` / ``download`` — summed live counters (``total_up`` /
      ``total_down``). ``total`` = upload + download + any *unused* quota
      headroom from the per-client data_limit, so Happ / v2rayN can show
      "X used of Y" correctly. When at least one key is unlimited, the
      aggregate is unlimited too (``total=0``).
    * ``expire`` — earliest ``expires_at`` across the set, or 0 if none
      of the keys expire. Clients read this as a Unix timestamp.
    """
    up_sum = 0
    down_sum = 0
    limit_sum = 0
    any_unlimited = False
    expire_ts = 0
    for c, _server in entries:
        up_sum += int(c.total_up or 0)
        down_sum += int(c.total_down or 0)
        if c.data_limit_bytes and c.data_limit_bytes > 0:
            limit_sum += int(c.data_limit_bytes)
        else:
            any_unlimited = True
        if c.expires_at is not None:
            try:
                ts = int(c.expires_at.timestamp())
            except (OSError, ValueError):
                ts = 0
            if ts > 0 and (expire_ts == 0 or ts < expire_ts):
                expire_ts = ts
    used = up_sum + down_sum
    total = 0 if any_unlimited else max(limit_sum, used)
    return (
        f"upload={up_sum}; download={down_sum}; "
        f"total={total}; expire={expire_ts}"
    )


_SubscriptionLike = Subscription  # type: ignore[misc]


def _utf8_header(value: str) -> str:
    """Make ``value`` safe for an HTTP header.

    Starlette (and the underlying ASGI stack) only encodes header values as
    latin-1. Admins routinely stuff flags and emoji ("🇷🇺", "🚀", …) into
    ``Profile-Title`` / announce copy, which trips ``UnicodeEncodeError``.
    VPN clients (Happ, v2rayN) in practice decode headers as UTF-8 despite
    the spec, so we serialise the UTF-8 bytes directly through latin-1
    — each byte stays intact on the wire and the client reconstructs the
    original text. ASCII strings pass through unchanged.
    """
    try:
        value.encode("latin-1")
        return value
    except UnicodeEncodeError:
        return value.encode("utf-8").decode("latin-1")


def _apply_subscription_customisation(
    headers: dict[str, str],
    *,
    profile_title: str,
    support_url: str,
    provider_id: str,
    routing: str,
    update_interval_hours: int,
    default_title: str,
) -> None:
    """Merge per-subscription customisation into an outgoing header dict.

    Fields left blank fall back to sensible defaults (``default_title``
    for the profile name, 24h for the refresh interval). Only non-empty
    values win — this keeps legacy rows behaving exactly as before.
    """
    title = (profile_title or "").strip() or default_title
    headers["Profile-Title"] = _utf8_header(title)
    headers["Profile-Update-Interval"] = str(max(1, int(update_interval_hours or 24)))
    if (support_url or "").strip():
        headers["Support-Url"] = _utf8_header(support_url.strip())
        # Happ is case-sensitive on some versions; mirror the lowercase
        # variant too so every client picks it up.
        headers["support-url"] = _utf8_header(support_url.strip())
    if (provider_id or "").strip():
        headers["X-Provider-ID"] = _utf8_header(provider_id.strip())
    if (routing or "").strip():
        headers["Routing"] = _utf8_header(routing.strip())


def _sub_headers(sub: Subscription, entries: list[tuple[Client, Server]]) -> dict[str, str]:
    headers: dict[str, str] = {
        "Subscription-Userinfo": _compute_userinfo(entries),
    }
    _apply_subscription_customisation(
        headers,
        profile_title=getattr(sub, "profile_title", "") or "",
        support_url=getattr(sub, "support_url", "") or "",
        provider_id=getattr(sub, "provider_id", "") or "",
        routing=getattr(sub, "routing", "") or "",
        update_interval_hours=int(getattr(sub, "update_interval_hours", 24) or 24),
        default_title=sub.name,
    )
    return headers


def _render_vless_plain(
    entries: list[tuple[Client, Server]],
    *,
    announce: str = "",
    provider_id: str = "",
    header_title: str = "",
    overrides: "Optional[dict[int, str]]" = None,
) -> str:
    """Render the plaintext vless:// list.

    Prepends an optional header block understood by Happ / v2rayN:

    * ``#<title>`` — the first comment line is shown as the subscription
      name by Happ. Populated from ``header_title`` when set.
    * ``providerid: <id>`` — Happ multi-provider hint (body copy of the
      ``X-Provider-ID`` header) — useful when the admin ships routing
      that references the provider.
    * ``#announce: <text>`` — informational banner Happ surfaces to the
      user above the server list. Multi-line announcements are joined
      with spaces so they remain a single ``#announce:`` line.
    """
    prefix_lines: list[str] = []
    title = (header_title or "").strip()
    if title:
        prefix_lines.append(f"#{title}")
    pid = (provider_id or "").strip()
    if pid:
        prefix_lines.append(f"providerid: {pid}")
    msg = " ".join((announce or "").split())
    if msg:
        prefix_lines.append(f"#announce: {msg}")
    if prefix_lines:
        prefix_lines.append("")  # blank separator for readability

    links = [
        build_vless_link(
            uuid=c.uuid,
            host=server.public_host,
            port=server.port,
            public_key=server.public_key,
            sni=server.sni,
            short_id=server.short_id,
            label=_subscription_label(server, c, overrides=overrides),
            flow=c.flow,
        )
        for c, server in entries
    ]
    body = prefix_lines + links
    return "\n".join(body) + ("\n" if body else "")


def _render_singbox(
    entries: list[tuple[Client, Server]],
    sub_name: str,
    *,
    overrides: "Optional[dict[int, str]]" = None,
) -> str:
    """Minimal sing-box subscription (outbounds only).

    Produces a valid config fragment that sing-box and Hiddify accept as a
    direct subscription — one vless outbound per active key, plus a selector
    referencing them. Clients can paste the URL into sing-box / Hiddify /
    NekoBox subscription boxes.
    """
    import json as _json

    outbounds: list[dict] = []
    tags: list[str] = []
    pool_tags: list[str] = []
    for c, server in entries:
        tag = _subscription_label(server, c, overrides=overrides)
        tags.append(tag)
        if bool(getattr(server, "in_pool", False)):
            pool_tags.append(tag)
        outbounds.append(
            {
                "type": "vless",
                "tag": tag,
                "server": server.public_host,
                "server_port": server.port,
                "uuid": c.uuid,
                "flow": c.flow or "xtls-rprx-vision",
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": server.sni,
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": server.public_key,
                        "short_id": server.short_id,
                    },
                },
            }
        )
    # Selector + urltest groups in front so users can pick a node.
    # Order matters: the first entry in ``outbounds`` is what sing-box
    # exposes as the default / what Hiddify pins at the top of its UI.
    if tags:
        # Global "pick best of everything" urltest.
        all_auto = {
            "type": "urltest",
            "tag": "auto",
            "outbounds": tags,
            "url": "https://www.gstatic.com/generate_204",
            "interval": "3m",
        }
        group_outbounds: list[dict] = [all_auto]
        selector_options: list[str] = ["auto"]
        default_choice = "auto"
        # If there's a configured pool (>= 1 server in_pool), surface it
        # as a separate urltest *above* the global auto so Hiddify /
        # sing-box use pool ping times as the default. We still keep
        # "auto" and the individual tags around as manual overrides.
        if pool_tags:
            pool_auto = {
                "type": "urltest",
                "tag": f"{POOL_PREFIX}Auto (Pool)",
                "outbounds": pool_tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "2m",
            }
            group_outbounds.insert(0, pool_auto)
            default_choice = pool_auto["tag"]
            selector_options = [pool_auto["tag"], "auto"]

        outbounds = group_outbounds + outbounds
        outbounds.insert(
            0,
            {
                "type": "selector",
                "tag": sub_name or "xnPanel",
                "outbounds": [*selector_options, *tags],
                "default": default_choice,
            },
        )
    doc = {"outbounds": outbounds}
    return _json.dumps(doc, ensure_ascii=False, indent=2)


def _render_clash(
    entries: list[tuple[Client, Server]],
    sub_name: str,
    *,
    overrides: "Optional[dict[int, str]]" = None,
) -> str:
    """Clash.Meta / Mihomo subscription (proxies + proxy-group).

    Emits a YAML fragment with vless+reality proxies and a single selector
    group. Mihomo and recent Clash.Meta builds support vless+reality fully.
    """
    import yaml  # type: ignore

    proxies: list[dict] = []
    names: list[str] = []
    pool_names: list[str] = []
    for c, server in entries:
        name = _subscription_label(server, c, overrides=overrides)
        names.append(name)
        if bool(getattr(server, "in_pool", False)):
            pool_names.append(name)
        proxies.append(
            {
                "name": name,
                "type": "vless",
                "server": server.public_host,
                "port": server.port,
                "uuid": c.uuid,
                "network": "tcp",
                "tls": True,
                "udp": True,
                "flow": c.flow or "xtls-rprx-vision",
                "servername": server.sni,
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": server.public_key,
                    "short-id": server.short_id,
                },
            }
        )
    # Build proxy-groups. One "auto" url-test over everything, one
    # "pool-auto" url-test over the subset marked in_pool, and a
    # top-level selector that defaults to pool-auto when populated.
    groups: list[dict] = []
    top_options: list[str] = []
    if names:
        if pool_names:
            groups.append(
                {
                    "name": f"{POOL_PREFIX}Auto (Pool)",
                    "type": "url-test",
                    "proxies": pool_names,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": 120,
                }
            )
            top_options.append(f"{POOL_PREFIX}Auto (Pool)")
        groups.append(
            {
                "name": "auto",
                "type": "url-test",
                "proxies": names,
                "url": "https://www.gstatic.com/generate_204",
                "interval": 180,
            }
        )
        top_options.append("auto")
    groups.append(
        {
            "name": sub_name or "xnPanel",
            "type": "select",
            "proxies": [*top_options, *names] or ["DIRECT"],
        }
    )
    doc = {"proxies": proxies, "proxy-groups": groups}
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


@app.get("/page/{token}", include_in_schema=False)
def public_subscription_page(
    token: str,
    request: Request,
    db: Session = Depends(get_db),
) -> HTMLResponse:
    """Public HTML landing page for a subscription token.

    Three states:
      * **not found** — token isn't a known TgBotUser or Subscription;
      * **expired**  — every issued client has elapsed;
      * **active**   — at least one active client exists.

    The branding (logo / colours / buy link / help text) is taken from
    the bot row whose user owns the token. Admin-issued subscription
    tokens get default branding.
    """
    base = tg_bots._subscription_base_url(db)
    bot_user = db.scalar(
        select(TgBotUser).where(TgBotUser.sub_token == token)
    )
    bot_row: Optional[TgBot] = None
    if bot_user is not None:
        bot_row = db.get(TgBot, bot_user.bot_id)
        base = tg_bots._subscription_base_url(db, bot=bot_row)
    branding = sub_page.PageBranding.from_bot(bot_row)
    sub_url = f"{base}/sub/{token}"

    if bot_user is not None:
        if bot_user.banned:
            return HTMLResponse(
                content=sub_page.render_expired(
                    branding,
                    expires_at=datetime.utcnow().replace(tzinfo=timezone.utc),
                ),
                status_code=403,
            )
        clients: list[Client] = []
        seen: set[int] = set()
        for c in list(bot_user.clients):
            if c.id in seen:
                continue
            seen.add(c.id)
            clients.append(c)
        if bot_user.client_id and bot_user.client_id not in seen:
            legacy = db.get(Client, bot_user.client_id)
            if legacy is not None:
                clients.append(legacy)
        active = [c for c in clients if c.is_active()]
        if not active:
            # Find latest known expiry for the "expired since" message.
            expired_at = max(
                (c.expires_at for c in clients if c.expires_at is not None),
                default=datetime.utcnow(),
            )
            if expired_at.tzinfo is None:
                expired_at = expired_at.replace(tzinfo=timezone.utc)
            return HTMLResponse(content=sub_page.render_expired(
                branding, expires_at=expired_at,
            ))
        # Take the latest expiry across all active clients (the "real"
        # window the user has on at least one server).
        expiries = [
            c.expires_at for c in active if c.expires_at is not None
        ]
        latest = max(expiries) if expiries else None
        if latest is not None and latest.tzinfo is None:
            latest = latest.replace(tzinfo=timezone.utc)
        return HTMLResponse(content=sub_page.render_active(
            branding, sub_url=sub_url, expires_at=latest,
        ))

    sub = db.scalar(
        select(Subscription).where(Subscription.token == token)
    )
    if sub is None:
        return HTMLResponse(
            content=sub_page.render_not_found(branding),
            status_code=404,
        )
    return HTMLResponse(content=sub_page.render_active(
        branding, sub_url=sub_url, expires_at=None,
    ))


@app.get("/sub/{token}", include_in_schema=False)
def public_subscription(
    token: str,
    request: Request,
    format: str = "",
    db: Session = Depends(get_db),
) -> Response:
    """Standard subscription feed.

    Default output: base64 of newline-joined vless:// links (compatible with
    v2rayN, Streisand, Hiddify, Shadowrocket, Nekoray…).

    Other formats via ``?format=``:
    - ``vless`` — plaintext vless:// list, no base64. Useful for debugging
      and for clients that reject base64 on HTTP endpoints.
    - ``singbox`` / ``sing-box`` — sing-box / Hiddify / NekoBox config JSON.
    - ``clash`` — Clash.Meta / Mihomo YAML.

    The token may match either a panel Subscription or a TgBotUser's
    per-user token; both paths record a device fingerprint so the
    anti-fraud loop can detect excessive device reuse.
    """
    fmt = (format or "").strip().lower()
    if fmt not in _SUBSCRIPTION_FORMATS:
        raise HTTPException(status_code=400, detail=f"unknown subscription format: {format}")

    # Fingerprint every fetch — used by the anti-fraud loop in tg_bots.py.
    user_agent = request.headers.get("user-agent", "")
    # X-Forwarded-For is set by Caddy's reverse proxy; fall back to the
    # socket peer for direct-to-panel deploys.
    ip = (
        request.headers.get("x-forwarded-for", "").split(",")[0].strip()
        or (request.client.host if request.client else "")
    )
    try:
        tg_bots.record_fingerprint(db, sub_token=token, user_agent=user_agent, ip=ip)
    except Exception:  # pragma: no cover — fingerprinting must never break sub
        pass

    # Path 1: bot-user subscription (per-tg-user token).
    bot_user = db.scalar(select(TgBotUser).where(TgBotUser.sub_token == token))
    if bot_user is not None:
        if bot_user.banned:
            raise HTTPException(status_code=403, detail="subscription blocked")
        # Collect every active client issued for this bot user. New-style
        # multi-server bots populate ``bot_user.clients`` via the
        # tg_bot_user_clients junction (one per server). Legacy
        # single-server bots only set ``client_id`` — include that too
        # so old users don't lose their existing key.
        client_objs: list[Client] = []
        seen: set[int] = set()
        for c in list(bot_user.clients):
            if c.id in seen:
                continue
            seen.add(c.id)
            client_objs.append(c)
        if bot_user.client_id and bot_user.client_id not in seen:
            legacy = db.get(Client, bot_user.client_id)
            if legacy is not None:
                client_objs.append(legacy)
        entries: list[tuple[Client, Server]] = []
        for c in client_objs:
            if c.is_active() and c.server is not None:
                entries.append((c, c.server))
        bot = bot_user.bot
        overrides: Optional[dict[int, str]] = None
        if bot is not None:
            overrides = tg_bots._bot_server_overrides(db, bot.id)
        # Stable ordering by server name so clients see a consistent list.
        entries.sort(key=lambda cs: (_server_label(cs[1], overrides=overrides), cs[0].id))
        default_title = f"xnPanel · @{bot_user.tg_username or bot_user.tg_user_id}"
        title_tpl = (getattr(bot, "profile_title", "") or "").strip() if bot else ""
        if title_tpl:
            try:
                default_title = title_tpl.format(
                    username=bot_user.tg_username or "",
                    tg_user_id=bot_user.tg_user_id or "",
                    first_name=bot_user.first_name or "",
                    bot=bot.name if bot else "",
                )
            except (KeyError, IndexError):
                # Bad placeholder — fall back to the literal template so
                # the admin sees their typo in the client UI.
                default_title = title_tpl
        headers: dict[str, str] = {
            "Subscription-Userinfo": _compute_userinfo(entries),
        }
        _apply_subscription_customisation(
            headers,
            profile_title=default_title,
            support_url=(getattr(bot, "support_url", "") or "") if bot else "",
            provider_id=(getattr(bot, "provider_id", "") or "") if bot else "",
            routing=(getattr(bot, "routing", "") or "") if bot else "",
            update_interval_hours=int(
                (getattr(bot, "update_interval_hours", 24) or 24) if bot else 24
            ),
            default_title=default_title,
        )
        return _render_subscription_response(
            entries, headers, fmt,
            sub_name=default_title,
            announce=(getattr(bot, "announce", "") or "") if bot else "",
            provider_id=(getattr(bot, "provider_id", "") or "") if bot else "",
            overrides=overrides,
        )

    sub = db.scalar(select(Subscription).where(Subscription.token == token))
    if sub is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    entries = _subscription_entries(sub, db)
    headers = _sub_headers(sub, entries)
    title = (getattr(sub, "profile_title", "") or "").strip() or sub.name
    return _render_subscription_response(
        entries, headers, fmt,
        sub_name=title,
        announce=getattr(sub, "announce", "") or "",
        provider_id=getattr(sub, "provider_id", "") or "",
    )


def _render_subscription_response(
    entries: list[tuple[Client, Server]],
    headers: dict[str, str],
    fmt: str,
    *,
    sub_name: str,
    announce: str = "",
    provider_id: str = "",
    overrides: "Optional[dict[int, str]]" = None,
) -> Response:
    if fmt in ("singbox", "sing-box", "json"):
        body = _render_singbox(entries, sub_name, overrides=overrides)
        return Response(
            content=body,
            media_type="application/json; charset=utf-8",
            headers=headers,
        )
    if fmt == "clash":
        body = _render_clash(entries, sub_name, overrides=overrides)
        return Response(
            content=body,
            media_type="text/yaml; charset=utf-8",
            headers=headers,
        )
    plaintext = _render_vless_plain(
        entries,
        announce=announce,
        provider_id=provider_id,
        header_title=sub_name,
        overrides=overrides,
    )
    if fmt == "vless":
        return PlainTextResponse(plaintext, headers=headers)

    # Default: base64(vless list) — legacy v2ray format.
    encoded = base64.b64encode(plaintext.encode()).decode()
    return PlainTextResponse(encoded, headers=headers)


# ---------- api tokens ----------
@app.get("/api/tokens", response_model=list[ApiTokenOut])
def api_list_tokens(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(
        select(ApiToken).where(ApiToken.user_id == user.id).order_by(ApiToken.id)
    ).all()
    # Never echo the secret back on list — only on create.
    return [
        {
            "id": t.id,
            "name": t.name,
            "token": None,
            "created_at": t.created_at,
            "last_used_at": t.last_used_at,
        }
        for t in rows
    ]


@app.post("/api/tokens", response_model=ApiTokenOut, status_code=201)
def api_create_token(
    body: ApiTokenCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    raw = _secrets.token_urlsafe(32)
    row = ApiToken(name=body.name, token=raw, user_id=user.id)
    db.add(row)
    db.commit()
    db.refresh(row)
    # Return the secret exactly once on creation.
    return {
        "id": row.id,
        "name": row.name,
        "token": raw,
        "created_at": row.created_at,
        "last_used_at": row.last_used_at,
    }


@app.delete("/api/tokens/{token_id}")
def api_delete_token(
    token_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    row = db.get(ApiToken, token_id)
    if row is None or row.user_id != user.id:
        raise HTTPException(status_code=404, detail="token not found")
    db.delete(row)
    db.commit()
    return {"ok": True}


# ---------- audit log ----------
@app.get("/api/logs", response_model=list[AuditLogOut])
def api_list_logs(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    action: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    q = select(AuditLog).order_by(AuditLog.id.desc())
    if action:
        q = q.where(AuditLog.action == action)
    q = q.limit(limit).offset(offset)
    rows = db.scalars(q).all()
    return [
        {
            "id": r.id,
            "user_id": r.user_id,
            "username": r.username,
            "action": r.action,
            "resource_type": r.resource_type,
            "resource_id": r.resource_id,
            "details": r.details,
            "created_at": r.created_at,
        }
        for r in rows
    ]


# ---------- telegram notifications ----------
@app.get("/api/notifications/telegram", response_model=TelegramConfigOut)
def api_get_telegram(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    bot_token, chat_id = audit_mod.telegram_config(db)
    return {"bot_token_set": bool(bot_token), "chat_id": chat_id}


@app.post("/api/notifications/telegram", response_model=TelegramConfigOut)
def api_set_telegram(
    body: TelegramConfigIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    # Empty bot_token clears it; non-empty persists as-is.
    audit_mod.setting_set(db, "telegram.bot_token", body.bot_token.strip())
    audit_mod.setting_set(db, "telegram.chat_id", body.chat_id.strip())
    db.commit()
    audit_mod.record(
        db, user=user, action="settings.telegram_update",
        details="configured" if body.bot_token and body.chat_id else "cleared",
        notify=False,
    )
    db.commit()
    bot_token, chat_id = audit_mod.telegram_config(db)
    return {"bot_token_set": bool(bot_token), "chat_id": chat_id}


@app.post("/api/notifications/telegram/test")
def api_test_telegram(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    ok = audit_mod.telegram_test(db, text=f"xnPanel: test notification from {user.username}")
    if not ok:
        raise HTTPException(status_code=400, detail="telegram send failed — проверь bot_token и chat_id")
    return {"ok": True}


# ---------- tg bots ----------
def _sanitise_referral_mode(value: "Optional[str]") -> str:
    """Coerce arbitrary input to one of ``off|days|percent``."""
    s = (value or "").strip().lower()
    if s in {"off", "days", "percent"}:
        return s
    return "off"


def _tg_bot_to_dict(b: TgBot, *, user_count: int, running: bool) -> dict:
    return {
        "id": b.id,
        "name": b.name,
        "owner_chat_id": b.owner_chat_id,
        "welcome_text": b.welcome_text,
        "default_server_id": b.default_server_id,
        "server_ids": sorted([s.id for s in b.servers]),
        "default_days": b.default_days,
        "default_data_limit_bytes": b.default_data_limit_bytes,
        "device_limit": b.device_limit,
        "profile_title": getattr(b, "profile_title", "") or "",
        "support_url": getattr(b, "support_url", "") or "",
        "announce": getattr(b, "announce", "") or "",
        "provider_id": getattr(b, "provider_id", "") or "",
        "routing": getattr(b, "routing", "") or "",
        "update_interval_hours": int(getattr(b, "update_interval_hours", 24) or 24),
        "subscription_domain": b.subscription_domain or "",
        "brand_name": b.brand_name or "",
        "logo_url": b.logo_url or "",
        "page_subtitle": b.page_subtitle or "",
        "page_help_text": b.page_help_text or "",
        "page_buy_url": b.page_buy_url or "",
        "referral_mode": b.referral_mode or "off",
        "referral_levels": int(b.referral_levels or 1),
        "referral_l1_days": int(b.referral_l1_days or 0),
        "referral_l2_days": int(b.referral_l2_days or 0),
        "referral_l3_days": int(b.referral_l3_days or 0),
        "referral_l1_percent": int(b.referral_l1_percent or 0),
        "referral_l2_percent": int(b.referral_l2_percent or 0),
        "referral_l3_percent": int(b.referral_l3_percent or 0),
        "referral_payout_url": b.referral_payout_url or "",
        "enabled": bool(b.enabled),
        "created_at": b.created_at,
        "user_count": user_count,
        "running": running,
    }


def _sync_bot_servers(db: Session, b: TgBot, server_ids: list[int]) -> None:
    """Replace ``b.servers`` with the servers referenced by ``server_ids``.

    Missing IDs are silently dropped — the caller is trusted (admin API).
    """
    if not server_ids:
        b.servers = []
        return
    rows = list(db.scalars(
        select(Server).where(Server.id.in_(server_ids))
    ).all())
    b.servers = rows


@app.get("/api/bots", response_model=list[TgBotOut])
def api_list_bots(
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = list(db.scalars(select(TgBot).order_by(TgBot.id)).all())
    # One grouped count query for user totals.
    counts = dict(db.execute(
        select(TgBotUser.bot_id, func.count(TgBotUser.id))
        .group_by(TgBotUser.bot_id)
    ).all())
    running_ids = set(tg_bots.manager.runners.keys())
    return [
        _tg_bot_to_dict(
            b, user_count=int(counts.get(b.id, 0)),
            running=(b.id in running_ids),
        )
        for b in rows
    ]


@app.post("/api/bots", response_model=TgBotOut, status_code=201)
def api_create_bot(
    body: TgBotCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    existing = db.scalar(select(TgBot).where(TgBot.bot_token == body.bot_token.strip()))
    if existing is not None:
        raise HTTPException(status_code=400, detail="этот bot_token уже добавлен")
    b = TgBot(
        name=body.name.strip(),
        bot_token=body.bot_token.strip(),
        owner_chat_id=body.owner_chat_id.strip(),
        welcome_text=body.welcome_text or "",
        default_server_id=body.default_server_id,
        default_days=int(body.default_days or 0),
        default_data_limit_bytes=int(body.default_data_limit_bytes or 0),
        device_limit=int(body.device_limit or 0),
        profile_title=(body.profile_title or "").strip(),
        support_url=(body.support_url or "").strip(),
        announce=(body.announce or "").strip(),
        provider_id=(body.provider_id or "").strip(),
        routing=(body.routing or "").strip(),
        update_interval_hours=int(body.update_interval_hours or 24),
        subscription_domain=(body.subscription_domain or "").strip(),
        brand_name=(body.brand_name or "").strip(),
        logo_url=(body.logo_url or "").strip(),
        page_subtitle=(body.page_subtitle or "").strip(),
        page_help_text=(body.page_help_text or ""),
        page_buy_url=(body.page_buy_url or "").strip(),
        referral_mode=_sanitise_referral_mode(body.referral_mode),
        referral_levels=max(1, min(3, int(body.referral_levels or 1))),
        referral_l1_days=int(body.referral_l1_days or 0),
        referral_l2_days=int(body.referral_l2_days or 0),
        referral_l3_days=int(body.referral_l3_days or 0),
        referral_l1_percent=max(0, min(100, int(body.referral_l1_percent or 0))),
        referral_l2_percent=max(0, min(100, int(body.referral_l2_percent or 0))),
        referral_l3_percent=max(0, min(100, int(body.referral_l3_percent or 0))),
        referral_payout_url=(body.referral_payout_url or "").strip(),
        enabled=bool(body.enabled),
    )
    db.add(b)
    db.flush()
    _sync_bot_servers(db, b, body.server_ids or [])
    audit_mod.record(db, user=user, action="bot.create",
                     resource_type="tg_bot", resource_id=b.id,
                     details=f"name={b.name}")
    db.commit()
    db.refresh(b)
    if b.subscription_domain:
        _kick_off_domain_provision(b.subscription_domain, db)
    return _tg_bot_to_dict(b, user_count=0, running=False)


@app.patch("/api/bots/{bot_id}", response_model=TgBotOut)
def api_update_bot(
    bot_id: int,
    body: TgBotUpdateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    b = db.get(TgBot, bot_id)
    if b is None:
        raise HTTPException(status_code=404, detail="bot not found")
    patch = body.model_dump(exclude_unset=True)
    old_subscription_domain = b.subscription_domain or ""
    if "bot_token" in patch:
        new_tok = (patch["bot_token"] or "").strip()
        if new_tok and new_tok != b.bot_token:
            clash = db.scalar(select(TgBot).where(
                TgBot.bot_token == new_tok, TgBot.id != b.id
            ))
            if clash is not None:
                raise HTTPException(status_code=400, detail="этот bot_token уже добавлен")
            b.bot_token = new_tok
        elif not new_tok:
            # Empty string is the 'no change' signal.
            patch.pop("bot_token", None)
    multiline_fields = {"welcome_text", "page_help_text", "announce", "routing"}
    for field in (
        "name", "owner_chat_id", "welcome_text", "default_server_id",
        "default_days", "default_data_limit_bytes", "device_limit", "enabled",
        "profile_title", "support_url", "announce", "provider_id", "routing",
        "update_interval_hours",
        "subscription_domain", "brand_name", "logo_url",
        "page_subtitle", "page_help_text", "page_buy_url",
        "referral_payout_url",
        "referral_l1_days", "referral_l2_days", "referral_l3_days",
        "referral_l1_percent", "referral_l2_percent", "referral_l3_percent",
        "referral_levels",
    ):
        if field in patch and patch[field] is not None:
            value = patch[field]
            if isinstance(value, str) and field not in multiline_fields:
                # Preserve newlines on multiline fields; strip trailing
                # whitespace on single-line fields so copy/paste from a
                # browser doesn't leave trailing spaces in headers.
                value = value.strip()
            if field in {"referral_l1_percent", "referral_l2_percent",
                         "referral_l3_percent"}:
                value = max(0, min(100, int(value)))
            elif field == "referral_levels":
                value = max(1, min(3, int(value)))
            setattr(b, field, value)
    if "referral_mode" in patch and patch["referral_mode"] is not None:
        b.referral_mode = _sanitise_referral_mode(patch["referral_mode"])
    if "server_ids" in patch and patch["server_ids"] is not None:
        _sync_bot_servers(db, b, list(patch["server_ids"]))
    audit_mod.record(db, user=user, action="bot.update",
                     resource_type="tg_bot", resource_id=b.id,
                     details=f"name={b.name}")
    db.commit()
    db.refresh(b)
    new_subscription_domain = b.subscription_domain or ""
    if new_subscription_domain and new_subscription_domain != old_subscription_domain:
        _kick_off_domain_provision(new_subscription_domain, db)
    counts = db.scalar(select(func.count(TgBotUser.id)).where(TgBotUser.bot_id == b.id)) or 0
    return _tg_bot_to_dict(b, user_count=int(counts),
                           running=(b.id in tg_bots.manager.runners))


def _kick_off_domain_provision(domain: str, db: Session) -> None:
    """Fire-and-forget LE+vhost provisioning so PATCH/POST returns fast."""
    import threading
    panel_port = int(os.environ.get("PANEL_PORT", "8443") or 8443)
    email = audit_mod.setting_get(db, "panel.acme_email", "") or os.environ.get("PANEL_EMAIL", "")

    def _run() -> None:
        try:
            res = domain_provision.provision(domain, panel_port=panel_port, email=email)
            log.info("domain auto-provision %s: ok=%s msg=%s", domain, res.ok, res.message)
        except Exception:
            log.exception("domain auto-provision crashed for %s", domain)

    threading.Thread(target=_run, name=f"domain-provision-{domain}", daemon=True).start()


@app.delete("/api/bots/{bot_id}")
def api_delete_bot(
    bot_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    b = db.get(TgBot, bot_id)
    if b is None:
        raise HTTPException(status_code=404, detail="bot not found")
    name = b.name
    db.delete(b)
    audit_mod.record(db, user=user, action="bot.delete",
                     resource_type="tg_bot", resource_id=bot_id,
                     details=f"name={name}")
    db.commit()
    return {"ok": True}


# ---------- per-bot plans ----------
def _bot_plan_to_dict(p: TgBotPlan) -> dict:
    return {
        "id": p.id,
        "bot_id": p.bot_id,
        "name": p.name,
        "duration_days": int(p.duration_days),
        "data_limit_bytes": int(p.data_limit_bytes or 0),
        "price_stars": int(p.price_stars or 0),
        "price_crypto_usdt_cents": int(p.price_crypto_usdt_cents or 0),
        "price_rub_kopecks": int(p.price_rub_kopecks or 0),
        "enabled": bool(p.enabled),
        "sort_order": int(p.sort_order or 0),
        "created_at": p.created_at,
    }


@app.get("/api/bots/{bot_id}/plans", response_model=list[BotPlanOut])
def api_list_bot_plans(
    bot_id: int,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if db.get(TgBot, bot_id) is None:
        raise HTTPException(status_code=404, detail="bot not found")
    rows = list(db.scalars(
        select(TgBotPlan).where(TgBotPlan.bot_id == bot_id)
        .order_by(TgBotPlan.sort_order.asc(), TgBotPlan.id.asc())
    ).all())
    return [_bot_plan_to_dict(p) for p in rows]


@app.post(
    "/api/bots/{bot_id}/plans", response_model=BotPlanOut, status_code=201
)
def api_create_bot_plan(
    bot_id: int,
    body: BotPlanCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if db.get(TgBot, bot_id) is None:
        raise HTTPException(status_code=404, detail="bot not found")
    p = TgBotPlan(
        bot_id=bot_id,
        name=body.name.strip(),
        duration_days=int(body.duration_days),
        data_limit_bytes=int(body.data_limit_bytes or 0),
        price_stars=int(body.price_stars or 0),
        price_crypto_usdt_cents=int(body.price_crypto_usdt_cents or 0),
        price_rub_kopecks=int(body.price_rub_kopecks or 0),
        enabled=bool(body.enabled),
        sort_order=int(body.sort_order or 0),
    )
    db.add(p)
    audit_mod.record(db, user=user, action="bot.plan.create",
                     resource_type="tg_bot", resource_id=bot_id,
                     details=f"name={p.name}")
    db.commit()
    db.refresh(p)
    return _bot_plan_to_dict(p)


@app.patch("/api/bots/{bot_id}/plans/{plan_id}", response_model=BotPlanOut)
def api_update_bot_plan(
    bot_id: int,
    plan_id: int,
    body: BotPlanIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    p = db.get(TgBotPlan, plan_id)
    if p is None or p.bot_id != bot_id:
        raise HTTPException(status_code=404, detail="plan not found")
    patch = body.model_dump(exclude_unset=True)
    for field in (
        "name", "duration_days", "data_limit_bytes",
        "price_stars", "price_crypto_usdt_cents", "price_rub_kopecks",
        "enabled", "sort_order",
    ):
        if field in patch and patch[field] is not None:
            value = patch[field]
            if field == "name" and isinstance(value, str):
                value = value.strip()
            setattr(p, field, value)
    audit_mod.record(db, user=user, action="bot.plan.update",
                     resource_type="tg_bot", resource_id=bot_id,
                     details=f"plan_id={p.id}")
    db.commit()
    db.refresh(p)
    return _bot_plan_to_dict(p)


@app.delete("/api/bots/{bot_id}/plans/{plan_id}")
def api_delete_bot_plan(
    bot_id: int,
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    p = db.get(TgBotPlan, plan_id)
    if p is None or p.bot_id != bot_id:
        raise HTTPException(status_code=404, detail="plan not found")
    db.delete(p)
    audit_mod.record(db, user=user, action="bot.plan.delete",
                     resource_type="tg_bot", resource_id=bot_id,
                     details=f"plan_id={plan_id}")
    db.commit()
    return {"ok": True}


# ---------- per-bot server display name overrides ----------
def _server_override_to_dict(o: BotServerOverride) -> dict:
    return {
        "id": o.id,
        "bot_id": o.bot_id,
        "server_id": o.server_id,
        "display_name": o.display_name or "",
    }


@app.get(
    "/api/bots/{bot_id}/server-overrides",
    response_model=list[BotServerOverrideOut],
)
def api_list_server_overrides(
    bot_id: int,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if db.get(TgBot, bot_id) is None:
        raise HTTPException(status_code=404, detail="bot not found")
    rows = list(db.scalars(
        select(BotServerOverride).where(BotServerOverride.bot_id == bot_id)
        .order_by(BotServerOverride.server_id)
    ).all())
    return [_server_override_to_dict(o) for o in rows]


@app.put(
    "/api/bots/{bot_id}/server-overrides",
    response_model=list[BotServerOverrideOut],
)
def api_replace_server_overrides(
    bot_id: int,
    body: list[BotServerOverrideIn],
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    if db.get(TgBot, bot_id) is None:
        raise HTTPException(status_code=404, detail="bot not found")
    # Replace-all semantics: simpler than maintaining row-level
    # diffs, and the override list is small (<= number of servers).
    db.execute(
        BotServerOverride.__table__.delete().where(
            BotServerOverride.bot_id == bot_id
        )
    )
    valid_server_ids = {
        sid for (sid,) in db.execute(select(Server.id)).all()
    }
    rows: list[BotServerOverride] = []
    for entry in body:
        if entry.server_id not in valid_server_ids:
            continue
        if not (entry.display_name or "").strip():
            continue
        rows.append(BotServerOverride(
            bot_id=bot_id,
            server_id=int(entry.server_id),
            display_name=entry.display_name.strip()[:128],
        ))
    db.add_all(rows)
    audit_mod.record(db, user=user, action="bot.server_overrides.replace",
                     resource_type="tg_bot", resource_id=bot_id,
                     details=f"count={len(rows)}")
    db.commit()
    out = list(db.scalars(
        select(BotServerOverride).where(BotServerOverride.bot_id == bot_id)
        .order_by(BotServerOverride.server_id)
    ).all())
    return [_server_override_to_dict(o) for o in out]


@app.get("/api/bots/{bot_id}/users", response_model=list[TgBotUserOut])
def api_list_bot_users(
    bot_id: int,
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    b = db.get(TgBot, bot_id)
    if b is None:
        raise HTTPException(status_code=404, detail="bot not found")
    users = list(db.scalars(
        select(TgBotUser).where(TgBotUser.bot_id == bot_id).order_by(TgBotUser.id.desc())
    ).all())
    # Count recent distinct fingerprints per user in a single query.
    horizon = datetime.utcnow() - timedelta(hours=24)
    fp_rows = list(db.execute(
        select(
            DeviceFingerprint.sub_token,
            func.count(func.distinct(DeviceFingerprint.fingerprint)),
        ).where(DeviceFingerprint.created_at >= horizon)
         .group_by(DeviceFingerprint.sub_token)
    ).all())
    counts = {tok: n for tok, n in fp_rows}
    return [
        {
            "id": u.id,
            "bot_id": u.bot_id,
            "tg_user_id": u.tg_user_id,
            "tg_username": u.tg_username,
            "first_name": u.first_name,
            "sub_token": u.sub_token,
            "client_id": u.client_id,
            "banned": bool(u.banned),
            "created_at": u.created_at,
            "device_count_24h": int(counts.get(u.sub_token, 0)),
        }
        for u in users
    ]


@app.post("/api/bots/{bot_id}/users/{user_id}/ban")
def api_ban_bot_user(
    bot_id: int,
    user_id: int,
    body: TgBotBanIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    bu = db.get(TgBotUser, user_id)
    if bu is None or bu.bot_id != bot_id:
        raise HTTPException(status_code=404, detail="bot user not found")
    tg_bots._apply_ban(db, bu, banned=bool(body.banned))
    db.commit()
    return {"ok": True, "banned": bool(bu.banned)}


# ---------- payments: plans ----------
def _plan_to_dict(p: Plan) -> dict:
    return {
        "id": p.id,
        "name": p.name,
        "duration_days": int(p.duration_days),
        "data_limit_bytes": int(p.data_limit_bytes or 0),
        "price_stars": int(p.price_stars or 0),
        "price_crypto_usdt_cents": int(p.price_crypto_usdt_cents or 0),
        "price_rub_kopecks": int(p.price_rub_kopecks or 0),
        "enabled": bool(p.enabled),
        "sort_order": int(p.sort_order or 0),
        "created_at": p.created_at,
    }


@app.get("/api/plans", response_model=list[PlanOut])
def api_list_plans(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(
        select(Plan).order_by(Plan.sort_order.asc(), Plan.id.asc())
    ).all()
    return [_plan_to_dict(p) for p in rows]


@app.post("/api/plans", response_model=PlanOut, status_code=201)
def api_create_plan(
    body: PlanCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    p = Plan(
        name=body.name,
        duration_days=body.duration_days,
        data_limit_bytes=body.data_limit_bytes,
        price_stars=body.price_stars,
        price_crypto_usdt_cents=body.price_crypto_usdt_cents,
        price_rub_kopecks=body.price_rub_kopecks,
        enabled=body.enabled,
        sort_order=body.sort_order,
    )
    db.add(p)
    db.commit()
    db.refresh(p)
    audit_mod.record(
        db, user=user, action="plan.create",
        resource_type="plan", resource_id=p.id,
        details=f"{p.name} ({p.duration_days}d)",
    )
    db.commit()
    return _plan_to_dict(p)


@app.patch("/api/plans/{plan_id}", response_model=PlanOut)
def api_update_plan(
    plan_id: int,
    body: PlanIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    p = db.get(Plan, plan_id)
    if p is None:
        raise HTTPException(status_code=404, detail="plan not found")
    updates = body.model_dump(exclude_unset=True)
    for k, v in updates.items():
        setattr(p, k, v)
    db.commit()
    db.refresh(p)
    audit_mod.record(
        db, user=user, action="plan.update",
        resource_type="plan", resource_id=p.id,
        details=",".join(sorted(updates.keys())),
    )
    db.commit()
    return _plan_to_dict(p)


@app.delete("/api/plans/{plan_id}")
def api_delete_plan(
    plan_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    p = db.get(Plan, plan_id)
    if p is None:
        raise HTTPException(status_code=404, detail="plan not found")
    name = p.name
    db.delete(p)
    db.commit()
    audit_mod.record(
        db, user=user, action="plan.delete",
        resource_type="plan", resource_id=plan_id,
        details=name,
    )
    db.commit()
    return {"ok": True}


# ---------- payments: settings ----------
@app.get("/api/payment-settings", response_model=PaymentSettingsOut)
def api_get_payment_settings(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = payments_mod.load_settings(db)
    return {
        "stars_enabled": s.stars_enabled,
        "cryptobot_enabled": s.cryptobot_enabled,
        "cryptobot_token_masked": payments_mod.mask_secret(s.cryptobot_token),
        "cryptobot_testnet": s.cryptobot_testnet,
        "freekassa_enabled": s.freekassa_enabled,
        "freekassa_merchant_id": s.freekassa_merchant_id,
        "freekassa_secret1_masked": payments_mod.mask_secret(s.freekassa_secret1),
        "freekassa_secret2_masked": payments_mod.mask_secret(s.freekassa_secret2),
        "freekassa_payment_system_id": s.freekassa_payment_system_id or "",
    }


@app.patch("/api/payment-settings", response_model=PaymentSettingsOut)
def api_update_payment_settings(
    body: PaymentSettingsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    updates = body.model_dump(exclude_unset=True)
    payments_mod.save_settings(db, **updates)
    db.commit()
    audit_mod.record(
        db, user=user, action="payments.settings.update",
        resource_type="payments", resource_id="settings",
        details=",".join(sorted(updates.keys())),
    )
    db.commit()
    return api_get_payment_settings(user=user, db=db)


# ---------- panel-wide settings ----------
def _panel_settings_dict(db: Session) -> dict:
    return {
        "subscription_url_base": audit_mod.setting_get(
            db, "panel.subscription_url_base", ""
        ),
        "public_url": audit_mod.setting_get(db, "panel.public_url", ""),
    }


@app.get("/api/panel-settings", response_model=PanelSettingsOut)
def api_get_panel_settings(
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    return _panel_settings_dict(db)


@app.patch("/api/panel-settings", response_model=PanelSettingsOut)
def api_update_panel_settings(
    body: PanelSettingsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    patch = body.model_dump(exclude_unset=True)
    keys = {
        "subscription_url_base": "panel.subscription_url_base",
        "public_url": "panel.public_url",
    }
    for field, key in keys.items():
        if field in patch and patch[field] is not None:
            audit_mod.setting_set(db, key, str(patch[field]).strip())
    audit_mod.record(
        db, user=user, action="panel.settings.update",
        resource_type="panel", resource_id="settings",
        details=",".join(sorted(patch.keys())),
    )
    db.commit()
    if "subscription_url_base" in patch and patch["subscription_url_base"]:
        _kick_off_domain_provision(str(patch["subscription_url_base"]).strip(), db)
    return _panel_settings_dict(db)


# ---------- domain provisioning (TLS + reverse proxy) ----------
@app.get("/api/domain/backend")
def api_domain_backend(_: User = Depends(current_user)) -> dict[str, str]:
    return {"backend": domain_provision.detect_backend()}


@app.get("/api/domain/status")
def api_domain_status(
    domain: str = Query(...),
    _: User = Depends(current_user),
) -> dict[str, object]:
    return domain_provision.status(domain)


@app.get("/api/domain/list")
def api_domain_list(_: User = Depends(current_user)) -> dict[str, object]:
    return {
        "backend": domain_provision.detect_backend(),
        "domains": domain_provision.list_provisioned(),
    }


@app.post("/api/domain/provision")
def api_domain_provision(
    body: DomainProvisionIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    panel_port = int(os.environ.get("PANEL_PORT", "8443") or 8443)
    email = audit_mod.setting_get(db, "panel.acme_email", "") or os.environ.get("PANEL_EMAIL", "")
    result = domain_provision.provision(body.domain, panel_port=panel_port, email=email)
    audit_mod.record(
        db, user=user, action="panel.domain.provision",
        resource_type="domain", resource_id=body.domain,
        details=("ok=" if result.ok else "err=") + result.message[:200],
    )
    db.commit()
    return result.to_dict()


@app.delete("/api/domain/provision")
def api_domain_unprovision(
    domain: str = Query(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    result = domain_provision.unprovision(domain)
    audit_mod.record(
        db, user=user, action="panel.domain.unprovision",
        resource_type="domain", resource_id=domain,
        details=("ok=" if result.ok else "err=") + result.message[:200],
    )
    db.commit()
    return result.to_dict()


# ---------- payments: orders ----------
def _order_to_dict(o: Order, *, bu: Optional[TgBotUser] = None) -> dict:
    return {
        "id": o.id,
        "bot_id": o.bot_id,
        "bot_user_id": o.bot_user_id,
        "plan_id": o.plan_id,
        "plan_name": o.plan_name or "",
        "plan_duration_days": int(o.plan_duration_days or 0),
        "provider": o.provider,
        "currency": o.currency or "",
        "amount": int(o.amount or 0),
        "provider_invoice_id": o.provider_invoice_id or "",
        "provider_ref": o.provider_ref or "",
        "status": o.status,
        "paid_at": o.paid_at,
        "applied_at": o.applied_at,
        "notes": o.notes or "",
        "created_at": o.created_at,
        "tg_user_id": (bu.tg_user_id if bu is not None else ""),
        "tg_username": (bu.tg_username if bu is not None else ""),
    }


@app.get("/api/orders", response_model=list[OrderOut])
def api_list_orders(
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    status: Optional[str] = Query(default=None),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    q = select(Order).order_by(Order.id.desc())
    if status:
        q = q.where(Order.status == status)
    q = q.limit(limit).offset(offset)
    rows = db.scalars(q).all()
    out: list[dict] = []
    for o in rows:
        bu = db.get(TgBotUser, o.bot_user_id) if o.bot_user_id else None
        out.append(_order_to_dict(o, bu=bu))
    return out


# ---------- payments: webhooks (public) ----------
@app.post("/api/pay/cryptobot/webhook", include_in_schema=False)
async def pay_cryptobot_webhook(
    request: Request, db: Session = Depends(get_db)
) -> dict:
    raw = await request.body()
    import json
    try:
        payload = json.loads(raw.decode("utf-8") or "{}")
    except Exception:
        raise HTTPException(status_code=400, detail="bad json")
    sig = request.headers.get("crypto-pay-api-signature", "")
    # Smuggle raw body through to the signature-verifying handler.
    payload["_raw_body"] = raw
    try:
        order = payments_mod.handle_cryptobot_webhook(
            db, payload=payload, signature=sig
        )
    except payments_mod.PaymentError as exc:
        log.warning("cryptobot webhook rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))
    if order is not None and order.status == "paid":
        try:
            await tg_bots.manager.notify_payment_success(order_id=order.id)
        except Exception as exc:  # pragma: no cover
            log.warning("post-cryptobot bot notify failed: %s", exc)
    return {"ok": True}


@app.api_route(
    "/api/pay/freekassa/callback",
    methods=["GET", "POST"],
    include_in_schema=False,
)
async def pay_freekassa_callback(
    request: Request, db: Session = Depends(get_db)
) -> PlainTextResponse:
    form_data = dict((await request.form()).multi_items()) if request.method == "POST" else dict(request.query_params)
    try:
        order = payments_mod.handle_freekassa_callback(db, form=form_data)
    except payments_mod.PaymentError as exc:
        log.warning("freekassa callback rejected: %s", exc)
        raise HTTPException(status_code=400, detail=str(exc))
    # FreeKassa expects the string "YES" on successful processing.
    if order is not None and order.status == "paid":
        # Best-effort notification back to the user in the bot.
        try:
            await tg_bots.manager.notify_payment_success(order_id=order.id)
        except Exception as exc:  # pragma: no cover
            log.warning("post-payment bot notify failed: %s", exc)
        return PlainTextResponse("YES")
    return PlainTextResponse("YES")


# ---------- UI ----------
@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui", status_code=302)


_HTML_NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate",
    "Pragma": "no-cache",
}


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def ui_index(request: Request) -> HTMLResponse:
    token = request.cookies.get(SESSION_COOKIE) or ""
    if not token:
        return RedirectResponse("/ui/login", status_code=302)  # type: ignore[return-value]
    return HTMLResponse(
        _render_shell(TEMPLATE_DIR / "app.html"),
        headers=_HTML_NO_CACHE_HEADERS,
    )


@app.get("/ui/login", response_class=HTMLResponse, include_in_schema=False)
def ui_login() -> HTMLResponse:
    return HTMLResponse(
        _render_shell(TEMPLATE_DIR / "login.html"),
        headers=_HTML_NO_CACHE_HEADERS,
    )


# Used by the installer / manual setup to bootstrap the first admin.
def _ensure_default_admin() -> None:
    """Create an admin user from env vars if no user exists yet."""
    from .database import SessionLocal

    username = os.environ.get("PANEL_INITIAL_USER")
    password = os.environ.get("PANEL_INITIAL_PASSWORD")
    if not username or not password:
        return
    with SessionLocal() as db:
        has_any = db.scalar(select(func.count()).select_from(User))
        if has_any:
            return
        db.add(User(username=username, password_hash=hash_password(password)))
        db.commit()


@app.on_event("startup")
def _bootstrap_admin() -> None:
    _ensure_default_admin()

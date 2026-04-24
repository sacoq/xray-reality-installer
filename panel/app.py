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
import os
import secrets as _secrets
import uuid as uuidlib
from datetime import datetime
from pathlib import Path
from typing import Iterable

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

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
from .models import ApiToken, Client, EnrollmentToken, Server, Subscription, User
from .schemas import (
    ApiTokenCreateIn,
    ApiTokenOut,
    ChangePasswordIn,
    ClientCreateIn,
    ClientOut,
    ClientUpdateIn,
    EnrollmentCreateIn,
    EnrollmentDetailsOut,
    EnrollmentOut,
    LoginIn,
    NodeCompleteIn,
    NodeCompleteOut,
    RebootIn,
    ServerCreateIn,
    ServerOut,
    ServerUpdateIn,
    SubscriptionCreateIn,
    SubscriptionOut,
    SubscriptionUpdateIn,
    XrayLogsOut,
)
from .xray_config import build_config, build_vless_link


# ---------- app ----------
app = FastAPI(title="xnPanel", version="1.1")

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"


@app.on_event("startup")
def _startup() -> None:
    init_db()


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
        "client_count": client_count if client_count is not None else len(s.clients),
    }


def _client_status(c: Client) -> str:
    if not bool(getattr(c, "enabled", True)):
        return "disabled"
    if c.is_expired():
        return "expired"
    if c.is_over_limit():
        return "limit"
    return "active"


def _client_to_dict(c: Client, server: Server) -> dict:
    link = build_vless_link(
        uuid=c.uuid,
        host=server.public_host,
        port=server.port,
        public_key=server.public_key,
        sni=server.sni,
        short_id=server.short_id,
        label=c.label or "xray-reality",
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


def _push_config(server: Server) -> None:
    """Regenerate xray config.json for ``server`` and push it to its agent.

    Only clients passing ``is_active()`` (enabled, not expired, under data
    limit) appear in the pushed config — over-limit or expired keys just
    disappear from xray's acceptors, which immediately cuts traffic without
    losing the DB row.
    """
    clients_payload = [
        {"id": c.uuid, "email": c.email, "flow": c.flow}
        for c in server.clients
        if c.is_active()
    ]
    config = build_config(
        port=server.port,
        sni=server.sni,
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=clients_payload,
    )
    AgentClient(server.agent_url, server.agent_token).put_config(config)


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
    return {"username": user.username}


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
        _push_config(server)
    except AgentError as e:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

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
    dirty_xray = False
    for field in ("name", "agent_url", "agent_token", "public_host", "port", "sni", "dest"):
        v = getattr(body, field, None)
        if v is None:
            continue
        if field in {"port", "sni", "dest"}:
            dirty_xray = True
        setattr(s, field, v)
    db.commit()
    if dirty_xray:
        try:
            _push_config(s)
        except AgentError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
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
    db.delete(s)
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
        clients_out.append(_client_to_dict(c, s))
    db.commit()

    if needs_push and online:
        try:
            _push_config(s)
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
    return [_client_to_dict(c, s) for c in s.clients]


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
        _push_config(s)
    except AgentError as e:
        db.delete(client)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

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
        _push_config(s)
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
        _push_config(s)
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
    db.delete(c)
    db.commit()
    db.refresh(s)

    try:
        _push_config(s)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {"ok": True}


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
        return AgentClient(s.agent_url, s.agent_token).reboot(delay_seconds=delay)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e


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
        _push_config(s)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
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
    enrollment = EnrollmentToken(
        token=_secrets.token_urlsafe(24),
        name=body.name,
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
    server = Server(
        name=e.name,
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
        _push_config(server)
    except AgentError as exc:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    e.used_at = datetime.utcnow()
    e.server_id = server.id
    db.commit()
    return {"ok": True, "server_id": server.id, "server_name": server.name}


# ---------- subscriptions ----------
def _subscription_clients(s: Subscription, db: Session) -> list[Client]:
    if s.include_all:
        return list(db.scalars(select(Client).order_by(Client.id)).all())
    return list(s.clients)


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


def _sub_headers(sub: Subscription) -> dict[str, str]:
    return {
        # v2rayN / Hiddify read these hints to show subscription name.
        "Profile-Title": sub.name,
        "Subscription-Userinfo": "upload=0; download=0; total=0; expire=0",
        "Profile-Update-Interval": "24",
    }


def _render_vless_plain(entries: list[tuple[Client, Server]]) -> str:
    links = [
        build_vless_link(
            uuid=c.uuid,
            host=server.public_host,
            port=server.port,
            public_key=server.public_key,
            sni=server.sni,
            short_id=server.short_id,
            label=f"{server.name} — {c.label or c.email}",
            flow=c.flow,
        )
        for c, server in entries
    ]
    return "\n".join(links) + ("\n" if links else "")


def _render_singbox(entries: list[tuple[Client, Server]], sub_name: str) -> str:
    """Minimal sing-box subscription (outbounds only).

    Produces a valid config fragment that sing-box and Hiddify accept as a
    direct subscription — one vless outbound per active key, plus a selector
    referencing them. Clients can paste the URL into sing-box / Hiddify /
    NekoBox subscription boxes.
    """
    import json as _json

    outbounds: list[dict] = []
    tags: list[str] = []
    for c, server in entries:
        tag = f"{server.name} · {c.label or c.email}"
        tags.append(tag)
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
    # Selector + auto-urltest in front so users can pick a node.
    if tags:
        outbounds.insert(
            0,
            {
                "type": "urltest",
                "tag": "auto",
                "outbounds": tags,
                "url": "https://www.gstatic.com/generate_204",
                "interval": "3m",
            },
        )
        outbounds.insert(
            0,
            {
                "type": "selector",
                "tag": sub_name or "xnPanel",
                "outbounds": ["auto", *tags],
                "default": "auto",
            },
        )
    doc = {"outbounds": outbounds}
    return _json.dumps(doc, ensure_ascii=False, indent=2)


def _render_clash(entries: list[tuple[Client, Server]], sub_name: str) -> str:
    """Clash.Meta / Mihomo subscription (proxies + proxy-group).

    Emits a YAML fragment with vless+reality proxies and a single selector
    group. Mihomo and recent Clash.Meta builds support vless+reality fully.
    """
    import yaml  # type: ignore

    proxies: list[dict] = []
    names: list[str] = []
    for c, server in entries:
        name = f"{server.name} · {c.label or c.email}"
        names.append(name)
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
    doc = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": sub_name or "xnPanel",
                "type": "select",
                "proxies": names or ["DIRECT"],
            }
        ],
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)


@app.get("/sub/{token}", include_in_schema=False)
def public_subscription(
    token: str,
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
    """
    fmt = (format or "").strip().lower()
    if fmt not in _SUBSCRIPTION_FORMATS:
        raise HTTPException(status_code=400, detail=f"unknown subscription format: {format}")

    sub = db.scalar(select(Subscription).where(Subscription.token == token))
    if sub is None:
        raise HTTPException(status_code=404, detail="subscription not found")
    entries = _subscription_entries(sub, db)
    headers = _sub_headers(sub)

    if fmt in ("singbox", "sing-box", "json"):
        body = _render_singbox(entries, sub.name)
        return Response(
            content=body,
            media_type="application/json; charset=utf-8",
            headers=headers,
        )
    if fmt == "clash":
        body = _render_clash(entries, sub.name)
        return Response(
            content=body,
            media_type="text/yaml; charset=utf-8",
            headers=headers,
        )
    if fmt == "vless":
        return PlainTextResponse(_render_vless_plain(entries), headers=headers)

    # Default: base64(vless list) — legacy v2ray format.
    encoded = base64.b64encode(_render_vless_plain(entries).encode()).decode()
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


# ---------- UI ----------
@app.get("/", include_in_schema=False)
def root() -> RedirectResponse:
    return RedirectResponse("/ui", status_code=302)


@app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
def ui_index(request: Request) -> HTMLResponse:
    token = request.cookies.get(SESSION_COOKIE) or ""
    if not token:
        return RedirectResponse("/ui/login", status_code=302)  # type: ignore[return-value]
    return HTMLResponse((TEMPLATE_DIR / "app.html").read_text())


@app.get("/ui/login", response_class=HTMLResponse, include_in_schema=False)
def ui_login() -> HTMLResponse:
    return HTMLResponse((TEMPLATE_DIR / "login.html").read_text())


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

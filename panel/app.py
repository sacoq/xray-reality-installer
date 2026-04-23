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
- GET  /api/servers/{id}/stats → traffic + sysinfo
- GET  /api/servers/{id}/clients
- POST /api/servers/{id}/clients
- DELETE /api/servers/{id}/clients/{client_id}
"""
from __future__ import annotations

import os
import secrets as _secrets
import uuid as uuidlib
from pathlib import Path
from typing import Iterable

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
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
from .models import Client, Server, User
from .schemas import (
    ChangePasswordIn,
    ClientCreateIn,
    ClientOut,
    LoginIn,
    ServerCreateIn,
    ServerOut,
    ServerUpdateIn,
)
from .xray_config import build_config, build_vless_link


# ---------- app ----------
app = FastAPI(title="xray-panel", version="1.0")

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
    }


def _short_id() -> str:
    return _secrets.token_hex(4)


def _push_config(server: Server) -> None:
    """Regenerate xray config.json for ``server`` and push it to its agent."""
    clients_payload = [
        {"id": c.uuid, "email": c.email, "flow": c.flow} for c in server.clients
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
    # if ever needed).
    clients_out: list[dict] = []
    for c in s.clients:
        t = traffic.get(c.email)
        if t:
            # xray stats are reset only when we ask; since we don't reset here,
            # we take the current max(live, stored).
            c.total_up = max(c.total_up, t["up"])
            c.total_down = max(c.total_down, t["down"])
        clients_out.append(_client_to_dict(c, s))
    db.commit()

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

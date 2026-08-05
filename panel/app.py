"""xray-panel FastAPI application.

Routes:
- GET  /                       → redirect to /ui
- GET  /ui                     → main SPA shell (served as HTML)
- GET  /ui/login               → login page
- POST /api/auth/login         → authenticate, set session cookie
- POST /api/auth/logout        → clear session
- POST /api/auth/password      → change password
- GET  /api/servers            → list servers (with live status)
- GET  /api/servers/live       → batch live snapshot (online clients + NIC rate per node)
- POST /api/servers            → add a new server (registers agent + pushes first config)
- GET  /api/servers/{id}       → server detail + clients
- PATCH /api/servers/{id}      → update server fields
- DELETE /api/servers/{id}
- POST /api/servers/{id}/xray/{action}   → restart|start|stop xray on the node
- GET  /api/servers/{id}/xray/logs       → journalctl -u xray -n N
- POST /api/servers/{id}/reboot          → reboot the host
- POST /api/servers/{id}/rotate-keys     → regenerate x25519 + push config
- POST /api/servers/{id}/resync          → rebuild + push config (no state change)
- GET  /api/servers/{id}/warp            → native WARP interface status
- POST /api/servers/{id}/warp/install    → install/activate warp-native
- POST /api/servers/{id}/tspu/check      → run cheburcheck immediately
- GET  /api/servers/{id}/stats → traffic + sysinfo + live (online clients, rates)
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
import json
import logging
import os
import re
import secrets as _secrets
import threading
import time
import uuid as uuidlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

import pyotp
from fastapi import (
    Depends,
    FastAPI,
    File,
    Form,
    HTTPException,
    Query,
    Request,
    Response,
    UploadFile,
)
from fastapi.openapi.utils import get_openapi
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import audit as audit_mod
from . import auto_balance
from . import backups
from . import domain_provision
from . import metrics_sync
from . import payments as payments_mod
from . import sub_page
from . import tg_bots
from . import traffic_sync
from . import tspu_check
from .agent_client import HEALTH_TIMEOUT, AgentClient, AgentError
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
    BridgeEnrollmentToken,
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
    client_effective_sni,
    effective_client_flow,
    normalise_transport,
    server_all_snis,
    server_tags,
    server_tspu_blocked_ips,
    server_tspu_checked_ips,
    server_transport,
    server_transport_path,
    server_warp_domains,
    transport_supports_flow,
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
    BackupRunOut,
    BackupImportApplyIn,
    BackupImportApplyOut,
    BackupImportPreviewOut,
    BackupSettingsIn,
    BackupSettingsOut,
    BulkCreateClientsIn,
    BulkDeleteClientsIn,
    BulkExtendClientsIn,
    BulkResultOut,
    ChangePasswordIn,
    ClientCreateIn,
    ClientOut,
    ClientUpdateIn,
    CustomNodeInspectIn,
    DomainProvisionIn,
    EnrollmentCreateIn,
    EnrollmentDetailsOut,
    EnrollmentOut,
    LoadBalancerSettingsIn,
    LoadBalancerSettingsOut,
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
    WarpInstallIn,
    XrayLogsOut,
    BridgeCompleteIn,
    BridgeEnrollmentCreateIn,
    BridgeEnrollmentDetailsOut,
    BridgeEnrollmentOut,
    SniEndpointProvisionIn,
)
from .hysteria_config import (
    HYSTERIA_AUTH_PASSWORD,
    PROTOCOL_HYSTERIA2,
    PROTOCOL_VLESS,
    build_hysteria_config,
    build_hysteria_link,
    is_hysteria2,
    normalise_auth_mode,
    normalise_listen as normalise_hysteria_listen,
    normalise_protocol,
)
from .xray_config import DEFAULT_WARP_DOMAINS, build_vless_link, normalise_warp_domains
from .xray_push import (
    WHITELIST_FRONT_MODE,
    custom_inbound_client_emails,
    delete_balancer_auth_clients,
    delete_bypass_auth_clients,
    is_balancer,
    is_custom,
    is_service_client,
    is_whitelist_front,
    push_config as _shared_push_config,
    rebuild_balancer_configs,
    rebuild_whitelist_front_configs,
)


# ---------- app ----------
log = logging.getLogger(__name__)

app = FastAPI(
    title="xnPanel API",
    version="1.2",
    description=(
        "Complete HTTP API for xnPanel administration. Browser sessions and "
        "Bearer API tokens are both supported; use the ApiToken authorization "
        "scheme for scripts and the interactive console."
    ),
)

_OPENAPI_TAGS = [
    {"name": "Authentication", "description": "Login, account security and 2FA."},
    {"name": "Servers", "description": "Node lifecycle, health and xray configuration."},
    {"name": "Clients", "description": "VLESS clients, quotas and bulk operations."},
    {"name": "Updates", "description": "Fleet version checks and restart-safe upgrades."},
    {"name": "Enrollments", "description": "One-time node installation and registration."},
    {"name": "Subscriptions", "description": "Provisioned multi-node subscription feeds."},
    {"name": "API tokens", "description": "Long-lived Bearer token management."},
    {"name": "Bots", "description": "Telegram bot, user and per-bot plan management."},
    {"name": "Billing", "description": "Plans, orders, providers and payment webhooks."},
    {"name": "Settings", "description": "Panel-wide and load-balancer settings."},
    {"name": "Domains", "description": "Subscription domain and TLS provisioning."},
    {"name": "Audit", "description": "Administrative audit log."},
    {"name": "Other"},
]


def _openapi_tag_for(path: str) -> str:
    if path.startswith("/api/auth/"):
        return "Authentication"
    if (
        path.startswith(("/api/admin/update", "/api/admin/upgrade"))
        or path.endswith("/version")
        or path.endswith("/upgrade")
    ):
        return "Updates"
    if "/clients" in path and path.startswith("/api/servers/"):
        return "Clients"
    if path.startswith("/api/servers") or path.startswith("/api/statistics"):
        return "Servers"
    if path.startswith("/api/enroll"):
        return "Enrollments"
    if path.startswith("/api/subscriptions"):
        return "Subscriptions"
    if path.startswith("/api/tokens"):
        return "API tokens"
    if path.startswith("/api/bots") or path.startswith("/api/notifications"):
        return "Bots"
    if path.startswith(("/api/plans", "/api/orders", "/api/pay", "/api/payment")):
        return "Billing"
    if path.startswith(("/api/panel-settings", "/api/load-balancer", "/api/backups")):
        return "Settings"
    if path.startswith("/api/domain"):
        return "Domains"
    if path.startswith("/api/logs"):
        return "Audit"
    return "Other"


def _custom_openapi() -> dict[str, Any]:
    if app.openapi_schema:
        return app.openapi_schema
    schema = get_openapi(
        title=app.title,
        version=app.version,
        description=app.description,
        routes=app.routes,
        tags=_OPENAPI_TAGS,
    )
    for path, path_item in schema.get("paths", {}).items():
        tag = _openapi_tag_for(path)
        for method, operation in path_item.items():
            if method.lower() in {"get", "post", "put", "patch", "delete"}:
                operation["tags"] = [tag]
    app.openapi_schema = schema
    return schema


app.openapi = _custom_openapi

STATIC_DIR = Path(__file__).parent / "static"
TEMPLATE_DIR = Path(__file__).parent / "templates"


def _render_shell(tpl: Path) -> str:
    """Return an HTML template with ?v=<mtime> appended to every local static
    asset include so upgrading the panel busts the browser cache for all
    users at once (no more 'кнопка не работает потому что старый JS')."""
    # Templates contain Cyrillic text and emoji; always decode explicitly so
    # local Windows development servers do not fall back to cp1251/ANSI.
    html = tpl.read_text(encoding="utf-8")
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
    # Periodically pull `xray api statsquery` from every node into
    # `Client.total_up`/`total_down`. External readers (xankaVPN bots'
    # traffic monitor) can then use the cheap DB-only `/api/servers/{id}/clients`
    # endpoint instead of the expensive `/api/servers/{id}/stats` one
    # which would itself fan out to every node's xray-core on every poll.
    await traffic_sync.manager.start()
    await metrics_sync.manager.start()
    await tspu_check.manager.start()
    await backups.manager.start()


@app.on_event("shutdown")
async def _shutdown() -> None:
    await tg_bots.manager.stop()
    await traffic_sync.manager.stop()
    await metrics_sync.manager.stop()
    await tspu_check.manager.stop()
    await backups.manager.stop()


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
    client_host, client_port = _server_client_endpoint(s)
    return {
        "id": s.id,
        "name": s.name,
        "display_name": getattr(s, "display_name", "") or "",
        "tags": server_tags(s),
        "warp_enabled": bool(getattr(s, "warp_enabled", False)),
        "warp_domains": server_warp_domains(s),
        "tspu_blocked": bool(getattr(s, "tspu_blocked", False)),
        "tspu_checked_at": getattr(s, "tspu_checked_at", None),
        "tspu_check_error": getattr(s, "tspu_check_error", "") or "",
        "tspu_checked_ips": server_tspu_checked_ips(s),
        "tspu_blocked_ips": server_tspu_blocked_ips(s),
        "in_pool": bool(getattr(s, "in_pool", False)),
        "pool_tier": auto_balance.server_pool_tier(s),
        "mode": (getattr(s, "mode", "") or "standalone"),
        "protocol": normalise_protocol(getattr(s, "protocol", "")),
        "upstream_server_id": getattr(s, "upstream_server_id", None),
        "agent_url": s.agent_url,
        "public_host": s.public_host,
        "port": s.port,
        # Keep the origin fields above for bridge diagnostics, but expose the
        # endpoint actually used in every generated client link explicitly.
        "client_public_host": client_host,
        "client_port": client_port,
        "client_endpoint": f"{client_host}:{client_port}",
        "sni": s.sni,
        "dest": s.dest,
        "snis": server_all_snis(s),
        "public_key": s.public_key,
        "short_id": s.short_id,
        "transport": server_transport(s),
        "transport_path": (getattr(s, "transport_path", "") or ""),
        "hysteria_listen": getattr(s, "hysteria_listen", "") or "",
        "hysteria_auth_mode": getattr(s, "hysteria_auth_mode", "userpass") or "userpass",
        "hysteria_auth_password": getattr(s, "hysteria_auth_password", "") or "",
        "hysteria_tls_mode": getattr(s, "hysteria_tls_mode", "acme") or "acme",
        "hysteria_acme_email": getattr(s, "hysteria_acme_email", "") or "",
        "hysteria_cert_path": getattr(s, "hysteria_cert_path", "") or "",
        "hysteria_key_path": getattr(s, "hysteria_key_path", "") or "",
        "hysteria_obfs_type": getattr(s, "hysteria_obfs_type", "") or "",
        "hysteria_obfs_password": getattr(s, "hysteria_obfs_password", "") or "",
        "hysteria_up_mbps": int(getattr(s, "hysteria_up_mbps", 0) or 0),
        "hysteria_down_mbps": int(getattr(s, "hysteria_down_mbps", 0) or 0),
        "hysteria_ignore_client_bandwidth": bool(
            getattr(s, "hysteria_ignore_client_bandwidth", False)
        ),
        "hysteria_congestion": getattr(s, "hysteria_congestion", "bbr") or "bbr",
        "hysteria_bbr_profile": getattr(s, "hysteria_bbr_profile", "standard")
        or "standard",
        "hysteria_disable_udp": bool(
            getattr(s, "hysteria_disable_udp", False)
        ),
        "hysteria_udp_idle_timeout": int(
            getattr(s, "hysteria_udp_idle_timeout", 60) or 60
        ),
        "hysteria_masquerade_url": getattr(
            s, "hysteria_masquerade_url", ""
        )
        or "",
        "hysteria_stats_port": int(
            getattr(s, "hysteria_stats_port", 9999) or 9999
        ),
        "hysteria_advanced_json": getattr(s, "hysteria_advanced_json", "") or "",
        "sni_endpoint_enabled": bool(
            getattr(s, "sni_endpoint_enabled", False)
        ),
        "sni_endpoint_domain": getattr(s, "sni_endpoint_domain", "") or "",
        "sni_endpoint_email": getattr(s, "sni_endpoint_email", "") or "",
        "sni_endpoint_port": int(
            getattr(s, "sni_endpoint_port", 9443) or 9443
        ),
        "bridge_enabled": bool(getattr(s, "bridge_enabled", False)),
        "bridge_name": getattr(s, "bridge_name", "") or "",
        "bridge_public_host": getattr(s, "bridge_public_host", "") or "",
        "bridge_port": int(getattr(s, "bridge_port", 443) or 443),
        "created_at": s.created_at,
        "online": online,
        "xray_version": xray_version,
        "xray_active": xray_active,
        "service_version": xray_version,
        "service_active": xray_active,
        # Hide panel-managed balancer auth rows from the headline
        # client count so admins only see real users.
        "client_count": (
            client_count
            if client_count is not None
            else sum(1 for c in s.clients if not is_service_client(c))
        ),
        "custom_inbound_tag": getattr(s, "custom_inbound_tag", "") or "",
        "config_locked": is_custom(s),
        "bandwidth_mbps": float(getattr(s, "bandwidth_mbps", 0.0) or 0.0),
        "speed_download_mbps": float(
            getattr(s, "speed_download_mbps", 0.0) or 0.0
        ),
        "speed_upload_mbps": float(
            getattr(s, "speed_upload_mbps", 0.0) or 0.0
        ),
        "speed_latency_ms": float(getattr(s, "speed_latency_ms", 0.0) or 0.0),
        "speed_tested_at": getattr(s, "speed_tested_at", None),
        "speed_test_error": getattr(s, "speed_test_error", "") or "",
        "hosting_provider": getattr(s, "hosting_provider", "") or "",
        "expires_at": getattr(s, "expires_at", None),
        "notification_bot_id": getattr(s, "notification_bot_id", None),
    }


def _normalise_node_expiry(value: Optional[datetime]) -> Optional[datetime]:
    """Store node lease dates as naive UTC values for SQLite comparisons."""
    if value is None:
        return None
    if value.tzinfo is not None:
        return value.astimezone(timezone.utc).replace(tzinfo=None)
    return value


def _validate_notification_bot(db: Session, bot_id: Optional[int]) -> Optional[int]:
    """Validate a selected reminder bot without requiring it to be enabled.

    Disabled bots are allowed so an admin can preconfigure a node before
    enabling the bot; the background scanner simply waits until it is running.
    """
    if bot_id is None:
        return None
    row = db.get(TgBot, int(bot_id))
    if row is None:
        raise HTTPException(status_code=400, detail="notification bot not found")
    return int(row.id)


def _client_status(c: Client) -> str:
    if not bool(getattr(c, "enabled", True)):
        return "disabled"
    if c.is_expired():
        return "expired"
    if c.is_over_limit():
        return "limit"
    return "active"


def _visible_client_clauses(server_id: int | None = None) -> list[Any]:
    clauses: list[Any] = [
        ~Client.label.in_(["__balancer__", "__bypass__"]),
        ~Client.email.like("__balancer__-%"),
        ~Client.email.like("__bypass__-%"),
    ]
    if server_id is not None:
        clauses.insert(0, Client.server_id == server_id)
    return clauses


def _server_client_counts(db: Session) -> dict[int, int]:
    rows = db.execute(
        select(Client.server_id, func.count(Client.id))
        .where(*_visible_client_clauses())
        .group_by(Client.server_id)
    ).all()
    return {int(server_id): int(count) for server_id, count in rows}


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
    prefix = auto_balance.label_prefix_for(server)
    if prefix:
        base = f"{prefix}{base}"
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


def _server_client_endpoint(server: Server) -> tuple[str, int]:
    """Return the public endpoint clients should dial.

    A managed HAProxy bridge changes only the TCP destination. Reality
    cryptographic fields and SNI still belong to the EU target server.
    """
    if (
        not is_hysteria2(server)
        and bool(getattr(server, "bridge_enabled", False))
        and (getattr(server, "bridge_public_host", "") or "").strip()
        and int(getattr(server, "bridge_port", 0) or 0) > 0
    ):
        return (
            (getattr(server, "bridge_public_host", "") or "").strip(),
            int(getattr(server, "bridge_port", 443) or 443),
        )
    return server.public_host, int(server.port)


def _prepare_hysteria_auth(mode: str | None, password: str | None) -> tuple[str, str]:
    """Canonicalise Hysteria auth and create a shared secret when requested.

    ``password`` mode follows the autosetup script and uses one URL-safe
    secret for the node. ``userpass`` keeps per-client UUID passwords and does
    not need a node-level secret.
    """
    try:
        auth_mode = normalise_auth_mode(mode)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    shared = (password or "").strip()
    if auth_mode == HYSTERIA_AUTH_PASSWORD and not shared:
        shared = _secrets.token_urlsafe(16)
    return auth_mode, shared


def _prepare_hysteria_obfs(obfs_type: str | None, obfs_password: str | None) -> tuple[str, str]:
    """Use Salamander by default for newly submitted Hysteria settings."""
    obfs = (obfs_type or "").strip().lower()
    secret = (obfs_password or "").strip()
    if obfs == "salamander" and not secret:
        secret = _secrets.token_urlsafe(16)
    return obfs, secret


def _client_connection_link(
    client: Client,
    server: Server,
    *,
    overrides: "Optional[dict[int, str]]" = None,
    label: str = "",
) -> str:
    host, port = _server_client_endpoint(server)
    effective_label = label or _subscription_label(
        server, client, overrides=overrides
    )
    if is_hysteria2(server):
        auth_mode = normalise_auth_mode(
            getattr(server, "hysteria_auth_mode", "userpass") or "userpass"
        )
        return build_hysteria_link(
            username="" if auth_mode == HYSTERIA_AUTH_PASSWORD else client.email,
            password=(
                getattr(server, "hysteria_auth_password", "") or client.uuid
                if auth_mode == HYSTERIA_AUTH_PASSWORD
                else client.uuid
            ),
            host=host,
            port=port,
            listen=getattr(server, "hysteria_listen", "") or "",
            sni=server.sni,
            label=effective_label,
            obfs_type=getattr(server, "hysteria_obfs_type", "") or "",
            obfs_password=getattr(server, "hysteria_obfs_password", "") or "",
            auth_mode=auth_mode,
        )
    return build_vless_link(
        uuid=client.uuid,
        host=host,
        port=port,
        public_key=server.public_key,
        sni=client_effective_sni(client, server),
        short_id=server.short_id,
        label=effective_label,
        flow=effective_client_flow(client, server) or "xtls-rprx-vision",
        transport=server_transport(server),
        transport_path=server_transport_path(server),
    )


def _hysteria_client_auth(client: Client, server: Server) -> str:
    """Return the password field expected by sing-box/Clash Hysteria2."""
    mode = normalise_auth_mode(
        getattr(server, "hysteria_auth_mode", "userpass") or "userpass"
    )
    if mode == HYSTERIA_AUTH_PASSWORD:
        return getattr(server, "hysteria_auth_password", "") or client.uuid
    return f"{client.email}:{client.uuid}"


def _client_to_dict(c: Client, server: Server) -> dict:
    sni = client_effective_sni(c, server)
    eff_flow = "" if is_hysteria2(server) else effective_client_flow(c, server)
    endpoint_host, endpoint_port = _server_client_endpoint(server)
    link = _client_connection_link(c, server)
    return {
        "id": c.id,
        "server_id": c.server_id,
        "uuid": c.uuid,
        "email": c.email,
        "label": c.label,
        "flow": eff_flow,
        "sni": sni,
        "sni_pinned": (
            False if is_hysteria2(server) else bool((c.sni or "").strip())
        ),
        "total_up": c.total_up,
        "total_down": c.total_down,
        "created_at": c.created_at,
        "vless_link": link,
        "connection_link": link,
        "client_public_host": endpoint_host,
        "client_port": endpoint_port,
        "client_endpoint": f"{endpoint_host}:{endpoint_port}",
        "protocol": normalise_protocol(getattr(server, "protocol", "")),
        "enabled": bool(getattr(c, "enabled", True)),
        "data_limit_bytes": getattr(c, "data_limit_bytes", None),
        "expires_at": getattr(c, "expires_at", None),
        "active": c.is_active(),
        "status": _client_status(c),
    }


def _short_id() -> str:
    return _secrets.token_hex(4)


def _push_config(
    server: Server,
    db: Session | None = None,
    *,
    remove_emails: Iterable[str] = (),
    reconcile_warp: bool = False,
) -> None:
    """Thin wrapper: delegate to shared ``xray_push.push_config`` but
    keep the module-local name so older call sites don't need touching.
    """
    _shared_push_config(
        server,
        db,
        remove_emails=remove_emails,
        reconcile_warp=reconcile_warp,
    )


# Plain-hostname pattern for SNI inputs. Conservative on purpose: a-z0-9
# plus dots and hyphens, 1-253 chars, no scheme, no port. xray rejects
# malformed serverNames at config-load anyway, but bouncing them at the
# API layer gives the admin a clean error instead of a 502 from the
# agent.
_SNI_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+$"
)


def _validate_sni(value: str) -> str:
    """Trim + sanity-check an SNI hostname. Returns the cleaned value.

    Raises HTTPException(400) on garbage. Used by every endpoint that
    takes an admin-supplied SNI (client-create, client-patch, the
    server-level SNI list endpoints).
    """
    sni = (value or "").strip().lower()
    if not sni:
        raise HTTPException(status_code=400, detail="sni cannot be empty")
    if ":" in sni or "/" in sni or " " in sni:
        raise HTTPException(
            status_code=400,
            detail="sni must be a plain hostname (no scheme, no port)",
        )
    if not _SNI_RE.match(sni):
        raise HTTPException(status_code=400, detail=f"invalid sni: {sni!r}")
    return sni


def _ensure_server_sni(server: Server, sni: str) -> bool:
    """Make sure ``sni`` is in the server's allowed list.

    If it's already there (either as ``server.sni`` or in
    ``extra_snis``) — no-op, returns False. Otherwise appends it to
    ``extra_snis`` and returns True so the caller knows it must
    re-push the inbound (xray's serverNames just changed).

    Caller is responsible for committing and re-pushing.
    """
    sni = _validate_sni(sni)
    if sni in server_all_snis(server):
        return False
    if is_custom(server):
        raise HTTPException(
            status_code=400,
            detail=(
                "custom node config is locked; choose an SNI already present "
                "in the imported inbound"
            ),
        )
    extras = [s.strip() for s in (server.extra_snis or "").split(",") if s.strip()]
    extras.append(sni)
    server.extra_snis = ",".join(extras)
    return True


def _set_server_extra_snis(server: Server, snis: list[str]) -> None:
    """Replace ``extra_snis`` with the given list (deduped, validated).

    The default ``server.sni`` is always implicitly allowed and is
    filtered out of ``extra_snis`` so the storage stays canonical.
    """
    base = (server.sni or "").strip().lower()
    seen: set[str] = set()
    if base:
        seen.add(base)
    out: list[str] = []
    for raw in snis:
        sni = _validate_sni(raw)
        if sni in seen:
            continue
        seen.add(sni)
        out.append(sni)
    server.extra_snis = ",".join(out)


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


# ---------- server-health cache ----------
#
# The panel UI hits ``GET /api/servers`` on every action and
# ``GET /api/servers/{id}/stats`` every 5 s while a server is
# selected; sitexanka also polls ``/api/servers`` (with its own 5-min
# TTL) to render subscription pages. Every one of those used to call
# ``AgentClient.health()`` synchronously per node with a 15 s
# timeout — so a single black-holed agent (TCP packets silently
# dropped, no RST) blocked the request 15 s, and N dead nodes
# serialised into N × 15 s.
#
# That alone was enough to starve the FastAPI thread pool
# (uvicorn defaults to ~40 threads via anyio): once they were all
# parked on health() calls, the panel UI and sitexanka stopped
# responding entirely until someone restarted xnpanel.
#
# Two fixes work together:
#
# 1. Probes use ``HEALTH_TIMEOUT`` (3 s) instead of the 15 s config-push
#    timeout. A live LAN agent answers in milliseconds; if it doesn't
#    respond in 3 s it's dead enough for the UI.
#
# 2. Results live in a short in-process TTL cache keyed by server id,
#    so the periodic poller doesn't re-probe the same dead node every
#    5 s — it reuses the last verdict for ``_HEALTH_CACHE_TTL`` seconds.
#    Mutating endpoints (create / update / restart / xray action /
#    rotate-keys etc.) call ``_invalidate_server_health`` so the next
#    poll re-probes immediately.
_HEALTH_CACHE_TTL = 10.0  # seconds


class _HealthEntry:
    __slots__ = ("online", "xray_version", "xray_active", "expires_at")

    def __init__(
        self,
        *,
        online: bool,
        xray_version: str,
        xray_active: bool,
        expires_at: float,
    ) -> None:
        self.online = online
        self.xray_version = xray_version
        self.xray_active = xray_active
        self.expires_at = expires_at


_server_health_cache: dict[int, _HealthEntry] = {}
_server_health_lock = threading.Lock()


def _health_cache_get(server_id: int) -> Optional[_HealthEntry]:
    """Return the cached entry for ``server_id`` if still fresh."""
    with _server_health_lock:
        entry = _server_health_cache.get(server_id)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            _server_health_cache.pop(server_id, None)
            return None
        return entry


def _health_cache_set(
    server_id: int,
    *,
    online: bool,
    xray_version: str,
    xray_active: bool,
) -> _HealthEntry:
    """Store a fresh entry with ``_HEALTH_CACHE_TTL`` window."""
    entry = _HealthEntry(
        online=online,
        xray_version=xray_version,
        xray_active=xray_active,
        expires_at=time.monotonic() + _HEALTH_CACHE_TTL,
    )
    with _server_health_lock:
        _server_health_cache[server_id] = entry
    return entry


def _invalidate_server_health(server_id: int) -> None:
    """Drop a server's cached health entry — call after mutating ops
    (config push, restart, rotate keys, delete) so the next poll
    re-probes instead of serving the stale value.
    """
    with _server_health_lock:
        _server_health_cache.pop(server_id, None)


def _probe_server_health(
    server: Server,
    *,
    timeout: float = HEALTH_TIMEOUT,
) -> _HealthEntry:
    """Hit the agent's ``/health`` and cache the verdict.

    Always returns an entry — failures cache as ``online=False``
    so a dead node stops monopolising threads on every poll.
    """
    online = False
    xray_version = ""
    xray_active = False
    try:
        h = AgentClient(
            server.agent_url, server.agent_token, timeout=timeout,
        ).health()
        online = True
        if is_hysteria2(server):
            xray_version = h.get("hysteria_version", "") or ""
            xray_active = bool(h.get("hysteria_active", False))
        else:
            xray_version = h.get("xray_version", "") or ""
            xray_active = bool(h.get("xray_active", False))
    except Exception:
        # Anything that doesn't come back as a clean health dict —
        # connect timeout, TLS handshake failure, HTTP 5xx, agent
        # restarting — is "offline" for UI purposes. We still cache
        # the negative so we don't re-probe again for the next
        # ``_HEALTH_CACHE_TTL`` seconds.
        online = False
    return _health_cache_set(
        server.id,
        online=online,
        xray_version=xray_version,
        xray_active=xray_active,
    )


def _get_server_health(
    server: Server,
    *,
    use_cache: bool = True,
) -> _HealthEntry:
    """Return health for ``server`` — cached if fresh, probed if not.

    Set ``use_cache=False`` for callers that want a fresh probe even
    inside the TTL window (e.g. UI buttons that explicitly ask "is
    this back yet?").
    """
    if use_cache:
        cached = _health_cache_get(server.id)
        if cached is not None:
            return cached
    return _probe_server_health(server)


def _probe_servers_parallel(servers: list[Server]) -> dict[int, _HealthEntry]:
    """Probe a batch of servers in parallel and return ``{id: entry}``.

    Reuses cached entries that are still fresh and only fires probes
    for the rest. All probes share a single short-lived
    ``ThreadPoolExecutor`` so total wall time ≈ ``HEALTH_TIMEOUT``
    instead of ``len(dead) × HEALTH_TIMEOUT``.
    """
    out: dict[int, _HealthEntry] = {}
    to_probe: list[Server] = []
    for s in servers:
        cached = _health_cache_get(s.id)
        if cached is not None:
            out[s.id] = cached
        else:
            to_probe.append(s)
    if not to_probe:
        return out

    # Cap parallelism at a sensible number so a panel hosting 50+
    # servers doesn't spawn 50 threads on every poll. 16 is enough
    # to keep total wall time near a single ``HEALTH_TIMEOUT``
    # window even for large pools.
    max_workers = min(16, len(to_probe))
    with ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="xnpanel-health"
    ) as pool:
        futures = {pool.submit(_probe_server_health, s): s for s in to_probe}
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                out[s.id] = fut.result()
            except Exception:
                # _probe_server_health already swallows agent errors,
                # so reaching here means something unexpected. Fall
                # back to a cached-offline entry rather than letting
                # one bad probe abort the whole listing.
                out[s.id] = _health_cache_set(
                    s.id,
                    online=False,
                    xray_version="",
                    xray_active=False,
                )
    return out


# ---------- live sessions / throughput cache ----------
#
# The dashboard's server cards show a live "online clients" counter and
# the host NIC rate (MB/s) for every node. Polling ``AgentClient.live()``
# once per node on every ``GET /api/servers`` call would double the
# per-poll latency (each ``/live`` round-trips the agent twice — once
# to seed the snapshot, then to read the delta) and hammer a black-holed
# agent. Instead we keep a short in-process TTL cache of the last live
# snapshot per server, refreshed by a dedicated ``GET /api/servers/live``
# batch endpoint that the UI polls on its own cadence (every ~8 s).
#
# ``/live`` on the agent is stateful — the first call seeds the baseline
# and only the *second* call returns meaningful rates. To avoid a 0/0
# flash on every cache miss we proactively seed the snapshot: when a
# server has no cached entry yet, the batch probe fires twice (with a
# short gap) so the panel already has real numbers by the time the UI
# reads them.
_LIVE_CACHE_TTL = 4.0  # shorter than the UI poll; agent responses are cached snapshots


class _LiveEntry:
    __slots__ = (
        "online_clients", "online_emails", "net_rx_bps", "net_tx_bps",
        "cpu_percent", "cpu_count", "load_1", "load_5", "load_15",
        "mem_total", "mem_used", "disk_total", "disk_used",
        "uptime_seconds", "sampled_at", "client_rates",
        "sample_window_s", "expires_at",
    )

    def __init__(
        self,
        *,
        online_clients: int,
        online_emails: list[str],
        net_rx_bps: int,
        net_tx_bps: int,
        cpu_percent: float,
        cpu_count: int,
        load_1: float,
        load_5: float,
        load_15: float,
        mem_total: int,
        mem_used: int,
        disk_total: int,
        disk_used: int,
        uptime_seconds: int,
        sampled_at: float,
        client_rates: dict[str, dict[str, int]],
        sample_window_s: float,
        expires_at: float,
    ) -> None:
        self.online_clients = online_clients
        self.online_emails = online_emails
        self.net_rx_bps = net_rx_bps
        self.net_tx_bps = net_tx_bps
        self.cpu_percent = cpu_percent
        self.cpu_count = cpu_count
        self.load_1 = load_1
        self.load_5 = load_5
        self.load_15 = load_15
        self.mem_total = mem_total
        self.mem_used = mem_used
        self.disk_total = disk_total
        self.disk_used = disk_used
        self.uptime_seconds = uptime_seconds
        self.sampled_at = sampled_at
        self.client_rates = client_rates
        self.sample_window_s = sample_window_s
        self.expires_at = expires_at


_server_live_cache: dict[int, _LiveEntry] = {}
_server_live_lock = threading.Lock()
# Track which servers we've already seeded this process lifetime so the
# batch poller can fire the second /live call after a short gap instead
# of returning all-zero rates on a cold cache.
_server_live_seeded: set[int] = set()


def _live_cache_get(server_id: int) -> Optional[_LiveEntry]:
    with _server_live_lock:
        entry = _server_live_cache.get(server_id)
        if entry is None:
            return None
        if time.monotonic() > entry.expires_at:
            _server_live_cache.pop(server_id, None)
            return None
        return entry


def _live_cache_set(server_id: int, entry: _LiveEntry) -> _LiveEntry:
    entry.expires_at = time.monotonic() + _LIVE_CACHE_TTL
    with _server_live_lock:
        _server_live_cache[server_id] = entry
    return entry


def _probe_server_live(server: Server, *, seed: bool = False) -> Optional[_LiveEntry]:
    """Fetch one ``/live`` snapshot from ``server``'s agent and cache it.

    Returns ``None`` on any agent error (dead node, /live 404 on an old
    agent) — callers treat that as "feature unavailable" and the UI
    falls back to ``client_count``.

    When ``seed`` is true we fire an extra throwaway ``/live`` first so
    the agent seeds its baseline counters; the second call (the one we
    actually cache) then has a real delta. Without this the very first
    batch poll after a panel restart reports 0 online / 0 B/s for every
    node until the next cycle.
    """
    agent = AgentClient(server.agent_url, server.agent_token, timeout=HEALTH_TIMEOUT)
    try:
        # New agents sample in the background, so one request always returns
        # the latest complete snapshot. ``seed`` remains in the signature for
        # compatibility with old call sites but no longer causes a double hit.
        data = agent.live()
    except Exception:  # noqa: BLE001 — dead node / unsupported agent
        return None
    client_rates: dict[str, dict[str, int]] = {}
    for c in data.get("clients") or []:
        email = c.get("email")
        if not email:
            continue
        client_rates[email] = {
            "up_bps": int(c.get("up_bps", 0) or 0),
            "down_bps": int(c.get("down_bps", 0) or 0),
            "online": bool(c.get("online", False)),
        }
    return _live_cache_set(
        server.id,
        _LiveEntry(
            online_clients=int(data.get("online_clients", 0) or 0),
            online_emails=list(data.get("online_emails") or []),
            net_rx_bps=int(data.get("net_rx_bps", 0) or 0),
            net_tx_bps=int(data.get("net_tx_bps", 0) or 0),
            cpu_percent=float(data.get("cpu_percent", 0.0) or 0.0),
            cpu_count=max(1, int(data.get("cpu_count", 1) or 1)),
            load_1=float(data.get("load_1", 0.0) or 0.0),
            load_5=float(data.get("load_5", 0.0) or 0.0),
            load_15=float(data.get("load_15", 0.0) or 0.0),
            mem_total=int(data.get("mem_total", 0) or 0),
            mem_used=int(data.get("mem_used", 0) or 0),
            disk_total=int(data.get("disk_total", 0) or 0),
            disk_used=int(data.get("disk_used", 0) or 0),
            uptime_seconds=int(data.get("uptime_seconds", 0) or 0),
            sampled_at=float(data.get("sampled_at", data.get("ts", 0.0)) or 0.0),
            client_rates=client_rates,
            sample_window_s=float(data.get("sample_window_s", 0.0) or 0.0),
            expires_at=0.0,  # set by _live_cache_set
        ),
    )


def _probe_servers_live(servers: list[Server]) -> dict[int, Optional[_LiveEntry]]:
    """Probe a batch of servers' ``/live`` in parallel and return ``{id: entry}``.

    Reuses fresh cache entries; only cold/Expired nodes hit the agent.
    First-poll nodes are seeded (two ``/live`` calls) so the UI gets real
    rates immediately instead of an all-zero cold-start flash.
    """
    out: dict[int, Optional[_LiveEntry]] = {}
    to_probe: list[Server] = []
    for s in servers:
        cached = _live_cache_get(s.id)
        if cached is not None:
            out[s.id] = cached
        else:
            to_probe.append(s)
    if not to_probe:
        return out

    max_workers = min(16, len(to_probe))
    with ThreadPoolExecutor(
        max_workers=max_workers, thread_name_prefix="xnpanel-live"
    ) as pool:
        futures = {
            pool.submit(_probe_server_live, s, seed=s.id not in _server_live_seeded): s
            for s in to_probe
        }
        for fut in as_completed(futures):
            s = futures[fut]
            try:
                entry = fut.result()
            except Exception:  # noqa: BLE001
                entry = None
            out[s.id] = entry
            # Mark as seeded regardless of outcome so we don't keep firing
            # the double-call on every cycle for a node whose agent is
            # permanently down (the seed call would just time out again).
            with _server_live_lock:
                _server_live_seeded.add(s.id)
    return out


def _live_entry_to_dict(
    entry: Optional[_LiveEntry], server: Server | None = None
) -> dict:
    """Public shape of a live snapshot, safe to embed in any JSON response.

    ``None`` (feature unavailable / dead node) serialises to a stub with
    ``available=False`` so the UI can ``x-show`` a fallback cleanly.
    """
    if entry is None:
        payload = {
            "available": False,
            "online_clients": 0,
            "net_rx_bps": 0,
            "net_tx_bps": 0,
            "cpu_percent": 0.0,
            "sample_window_s": 0.0,
        }
        return metrics_sync.enrich_live_payload(server, payload) if server else payload
    payload = {
        "available": True,
        "online_clients": entry.online_clients,
        "net_rx_bps": entry.net_rx_bps,
        "net_tx_bps": entry.net_tx_bps,
        "cpu_percent": entry.cpu_percent,
        "cpu_count": entry.cpu_count,
        "load_1": entry.load_1,
        "load_5": entry.load_5,
        "load_15": entry.load_15,
        "mem_total": entry.mem_total,
        "mem_used": entry.mem_used,
        "disk_total": entry.disk_total,
        "disk_used": entry.disk_used,
        "uptime_seconds": entry.uptime_seconds,
        "sampled_at": entry.sampled_at,
        "sample_window_s": entry.sample_window_s,
    }
    return metrics_sync.enrich_live_payload(server, payload) if server else payload


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
def _normalise_server_tags(values: Iterable[str] | None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    for raw in values or []:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        if len(value) > 64 or any(ord(ch) < 32 for ch in value):
            raise HTTPException(status_code=400, detail=f"invalid node tag: {value!r}")
        out.append(value)
        seen.add(value)
    if len(out) > 32:
        raise HTTPException(status_code=400, detail="at most 32 node tags are allowed")
    return out


def _normalise_server_warp_domains(
    values: Iterable[str] | None,
    *,
    enabled: bool,
) -> list[str]:
    source = list(values or [])
    if enabled and not source:
        source = list(DEFAULT_WARP_DOMAINS)
    try:
        cleaned = normalise_warp_domains(source)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if enabled and not cleaned:
        raise HTTPException(
            status_code=400, detail="WARP domain list cannot be empty when enabled"
        )
    return cleaned


def _require_active_warp_agent(agent: AgentClient) -> dict:
    try:
        result = agent.warp_status()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400,
            detail=f"could not verify WARP on node; install/update the agent first: {exc}",
        ) from exc
    if not bool(result.get("reachable")):
        raise HTTPException(
            status_code=400,
            detail=(result.get("message") or "WARP is not installed or not reachable"),
        )
    return result


def _require_active_warp(server: Server) -> dict:
    return _require_active_warp_agent(
        AgentClient(server.agent_url, server.agent_token, timeout=30)
    )


@app.get("/api/servers", response_model=list[ServerOut])
def api_list_servers(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    rows = db.scalars(select(Server).order_by(Server.id)).all()
    client_counts = _server_client_counts(db)
    # Probe every node in parallel with a short ``HEALTH_TIMEOUT``
    # and reuse the TTL cache so a single dead agent can't serialise
    # the listing into N × 15 s. See the ``server-health cache``
    # block above for the cascade this fixes.
    health = _probe_servers_parallel(list(rows))
    out: list[dict] = []
    for s in rows:
        entry = health.get(s.id)
        out.append(
            _server_to_dict(
                s,
                online=entry.online if entry else False,
                xray_version=entry.xray_version if entry else "",
                xray_active=entry.xray_active if entry else False,
                client_count=client_counts.get(s.id, 0),
            )
        )
    return out


@app.get("/api/servers/live")
def api_servers_live(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Live per-node snapshot for the dashboard server cards.

    Returns ``{servers: {id: {online_clients, net_rx_bps, net_tx_bps,
    cpu_percent, available}}, ts}``. The UI polls this on its own ~8 s
    cadence (independent of ``GET /api/servers``) so the headline
    client-count and throughput numbers refresh without re-walking the
    full server list. Results come from the in-process live cache;
    expired/missing entries are probed in parallel here.

    Only online nodes return ``available=True`` — a node that's health-
    offline (or running an old agent without ``/live``) reports
    ``available=False`` and the card falls back to ``client_count``.
    """
    rows = db.scalars(select(Server).order_by(Server.id)).all()
    # Skip the live probe for nodes the health cache already knows are
    # offline — /live would just time out against a dead agent.
    health = _probe_servers_parallel(list(rows))
    online_servers = [s for s in rows if health.get(s.id) and health[s.id].online]
    live = _probe_servers_live(online_servers)
    out: dict[int, dict] = {}
    for s in rows:
        h = health.get(s.id)
        if not (h and h.online):
            out[s.id] = _live_entry_to_dict(None, s)
            out[s.id]["online"] = False
            continue
        d = _live_entry_to_dict(live.get(s.id), s)
        d["online"] = True
        out[s.id] = d
    return {"servers": out, "ts": time.time()}


@app.get("/api/statistics")
def api_statistics(
    period: str = Query(default="30d"),
    server_id: int = Query(default=0, ge=0),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    del user
    try:
        return metrics_sync.statistics_payload(
            db, period=period, server_id=server_id
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


@app.post("/api/servers/{server_id}/speedtest")
def api_run_server_speedtest(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if db.get(Server, server_id) is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        result = metrics_sync.run_speedtest_for_server(server_id)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="server.speedtest",
        resource_type="server",
        resource_id=server_id,
        details=(
            result.get("error")
            or f"down={result['download_mbps']} up={result['upload_mbps']}"
        ),
    )
    db.commit()
    return result


@app.post("/api/servers/custom/inspect")
def api_inspect_custom_node(
    body: CustomNodeInspectIn,
    user: User = Depends(current_user),
) -> dict:
    """Inspect existing importable inbounds before creating a custom node."""
    del user
    agent = AgentClient(body.agent_url, body.agent_token, timeout=HEALTH_TIMEOUT)
    try:
        health = agent.health()
        inbounds = agent.inbounds()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"could not inspect node agent: {exc}"
        ) from exc
    return {"health": health, "inbounds": inbounds}


@app.get("/api/servers/{server_id}/warp")
def api_server_warp_status(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    del user
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        return AgentClient(
            server.agent_url, server.agent_token, timeout=30
        ).warp_status()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/api/servers/{server_id}/warp/install")
def api_server_warp_install(
    server_id: int,
    body: WarpInstallIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        result = AgentClient(server.agent_url, server.agent_token).warp_install(
            license_key=body.license_key
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="server.warp_install",
        resource_type="server",
        resource_id=server.id,
        details=f"reachable={bool(result.get('reachable'))} ip={result.get('warp_ip', '')}",
    )
    db.commit()
    return result


@app.post("/api/servers/{server_id}/tspu/check")
def api_server_tspu_check(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    del user
    if db.get(Server, server_id) is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        return tspu_check.check_server_now(server_id)
    except LookupError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=str(exc)) from exc


def _create_custom_server(
    body: ServerCreateIn, user: User, db: Session
) -> dict:
    tag = (body.custom_inbound_tag or "").strip()
    if not tag:
        raise HTTPException(status_code=400, detail="custom_inbound_tag is required")
    agent = AgentClient(body.agent_url, body.agent_token, timeout=HEALTH_TIMEOUT)
    try:
        health = agent.health()
        descriptors = agent.inbounds()
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"could not inspect node agent: {exc}"
        ) from exc
    descriptor = next((item for item in descriptors if item.get("tag") == tag), None)
    if descriptor is None:
        raise HTTPException(
            status_code=400, detail=f"VLESS+Reality inbound {tag!r} not found"
        )

    server_names = [
        _validate_sni(str(value))
        for value in descriptor.get("server_names") or []
        if value
    ]
    if not server_names:
        raise HTTPException(
            status_code=400, detail="selected inbound has no Reality serverNames"
        )
    public_key = str(descriptor.get("public_key") or body.public_key or "").strip()
    if not public_key:
        raise HTTPException(
            status_code=400,
            detail=(
                "agent could not derive the Reality public key; update xray/agent "
                "or provide public_key"
            ),
        )
    short_ids = [str(value) for value in descriptor.get("short_ids") or []]
    short_id = str(body.short_id or (short_ids[0] if short_ids else ""))
    port = int(descriptor.get("port") or 0)
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="selected inbound has an invalid port")
    try:
        transport = normalise_transport(str(descriptor.get("transport") or "tcp"))
        tier = auto_balance.normalise_tier(body.pool_tier)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if not tier and body.in_pool:
        tier = auto_balance.TIER_PRIMARY
    node_tags = _normalise_server_tags(body.tags)
    warp_domains = _normalise_server_warp_domains(
        body.warp_domains, enabled=bool(body.warp_enabled)
    )
    if body.warp_enabled:
        _require_active_warp_agent(agent)

    server = Server(
        name=body.name,
        display_name=(body.display_name or "").strip(),
        tags=json.dumps(node_tags, ensure_ascii=False),
        warp_enabled=bool(body.warp_enabled),
        warp_domains=json.dumps(warp_domains, ensure_ascii=False),
        in_pool=tier == auto_balance.TIER_PRIMARY,
        pool_tier=tier,
        mode="custom",
        custom_inbound_tag=tag,
        agent_url=body.agent_url.rstrip("/"),
        agent_token=body.agent_token,
        public_host=body.public_host,
        port=port,
        sni=server_names[0],
        extra_snis=",".join(server_names[1:]),
        dest=str(descriptor.get("dest") or ""),
        transport=transport,
        transport_path=str(descriptor.get("transport_path") or ""),
        private_key="",
        public_key=public_key,
        short_id=short_id,
        bandwidth_mbps=float(body.bandwidth_mbps or 0.0),
        hosting_provider=(body.hosting_provider or "").strip(),
        expires_at=_normalise_node_expiry(body.expires_at),
        notification_bot_id=_validate_notification_bot(db, body.notification_bot_id),
    )
    db.add(server)
    db.commit()
    db.refresh(server)
    provisioned_count = _provision_all_server_subscriptions_for_server(server, db)
    if server.warp_enabled or provisioned_count:
        try:
            _push_config(server, db)
        except AgentError as exc:
            db.delete(server)
            db.commit()
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if auto_balance.is_in_auto_balance(server):
        rebuild_balancer_configs(db)
    audit_mod.record(
        db,
        user=user,
        action="server.create",
        resource_type="server",
        resource_id=server.id,
        details=f"{server.name} custom inbound={tag}",
    )
    db.commit()
    return _server_to_dict(
        server,
        online=True,
        xray_version=str(health.get("xray_version") or ""),
        xray_active=bool(health.get("xray_active", False)),
        client_count=0,
    )


@app.post("/api/servers", response_model=ServerOut, status_code=201)
def api_create_server(
    body: ServerCreateIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    if db.scalar(select(Server).where(Server.name == body.name)):
        raise HTTPException(status_code=400, detail="a server with this name already exists")

    try:
        protocol = normalise_protocol(body.protocol)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if (body.mode or "standalone") == "custom":
        if protocol != PROTOCOL_VLESS:
            raise HTTPException(
                status_code=400, detail="custom import supports VLESS+Reality only"
            )
        return _create_custom_server(body, user, db)

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
    if protocol == PROTOCOL_VLESS and (not private_key or not public_key):
        try:
            kp = agent.gen_keypair()
            private_key = kp["private_key"]
            public_key = kp["public_key"]
        except Exception as e:  # noqa: BLE001
            raise HTTPException(status_code=400, detail=f"keypair generation failed: {e}") from e

    # Reconcile in_pool / pool_tier so the row's two flags never drift.
    # Rules: ``pool_tier='primary'`` ↔ ``in_pool=True``; any other tier
    # forces ``in_pool=False``. ``in_pool=True`` without an explicit
    # tier auto-fills ``primary`` (legacy compat).
    try:
        tier = auto_balance.normalise_tier(body.pool_tier)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    in_pool = bool(body.in_pool)
    if tier == auto_balance.TIER_PRIMARY:
        in_pool = True
    elif tier == auto_balance.TIER_FALLBACK:
        in_pool = False
    elif in_pool:
        tier = auto_balance.TIER_PRIMARY
    try:
        new_transport = normalise_transport(body.transport)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    new_transport_path = (body.transport_path or "").strip()
    hysteria_auth_mode = (body.hysteria_auth_mode or "userpass").strip().lower()
    hysteria_auth_password = (body.hysteria_auth_password or "").strip()
    hysteria_obfs_type = (body.hysteria_obfs_type or "").strip().lower()
    hysteria_obfs_password = (body.hysteria_obfs_password or "").strip()
    if protocol == PROTOCOL_HYSTERIA2:
        hysteria_auth_mode, hysteria_auth_password = _prepare_hysteria_auth(
            hysteria_auth_mode, hysteria_auth_password
        )
        hysteria_obfs_type, hysteria_obfs_password = _prepare_hysteria_obfs(
            hysteria_obfs_type, hysteria_obfs_password
        )
    node_tags = _normalise_server_tags(body.tags)
    warp_domains = _normalise_server_warp_domains(
        body.warp_domains, enabled=bool(body.warp_enabled)
    )
    if body.warp_enabled:
        if protocol == PROTOCOL_HYSTERIA2:
            raise HTTPException(
                status_code=400, detail="WARP is not supported on Hysteria 2 nodes"
            )
        _require_active_warp_agent(agent)
    if protocol == PROTOCOL_HYSTERIA2:
        try:
            body.sni = _validate_sni(body.sni)
            build_hysteria_config(
                port=body.port,
                listen=body.hysteria_listen,
                sni=body.sni,
                tls_mode=body.hysteria_tls_mode,
                acme_email=body.hysteria_acme_email,
                cert_path=body.hysteria_cert_path,
                key_path=body.hysteria_key_path,
                clients=[],
                auth_mode=hysteria_auth_mode,
                auth_password=hysteria_auth_password,
                stats_secret="manual-create-validation",
                stats_port=body.hysteria_stats_port,
                obfs_type=hysteria_obfs_type,
                obfs_password=hysteria_obfs_password,
                up_mbps=body.hysteria_up_mbps,
                down_mbps=body.hysteria_down_mbps,
                ignore_client_bandwidth=body.hysteria_ignore_client_bandwidth,
                congestion=body.hysteria_congestion,
                bbr_profile=body.hysteria_bbr_profile,
                disable_udp=body.hysteria_disable_udp,
                udp_idle_timeout_seconds=body.hysteria_udp_idle_timeout,
                masquerade_url=body.hysteria_masquerade_url,
                advanced_json=body.hysteria_advanced_json,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    server = Server(
        name=body.name,
        display_name=(body.display_name or "").strip(),
        tags=json.dumps(node_tags, ensure_ascii=False),
        warp_enabled=bool(body.warp_enabled),
        warp_domains=json.dumps(warp_domains, ensure_ascii=False),
        in_pool=in_pool,
        pool_tier=tier,
        protocol=protocol,
        agent_url=body.agent_url.rstrip("/"),
        agent_token=body.agent_token,
        public_host=body.public_host,
        port=body.port,
        sni=body.sni,
        dest=body.dest,
        transport=new_transport,
        transport_path=new_transport_path,
        private_key=private_key if protocol == PROTOCOL_VLESS else "",
        public_key=public_key if protocol == PROTOCOL_VLESS else "",
        short_id=(body.short_id or _short_id()) if protocol == PROTOCOL_VLESS else "",
        hysteria_listen=body.hysteria_listen.strip(),
        hysteria_auth_mode=hysteria_auth_mode,
        hysteria_auth_password=hysteria_auth_password,
        hysteria_tls_mode=body.hysteria_tls_mode,
        hysteria_acme_email=body.hysteria_acme_email.strip(),
        hysteria_cert_path=body.hysteria_cert_path.strip(),
        hysteria_key_path=body.hysteria_key_path.strip(),
        hysteria_obfs_type=hysteria_obfs_type,
        hysteria_obfs_password=hysteria_obfs_password,
        hysteria_up_mbps=body.hysteria_up_mbps,
        hysteria_down_mbps=body.hysteria_down_mbps,
        hysteria_ignore_client_bandwidth=body.hysteria_ignore_client_bandwidth,
        hysteria_congestion=body.hysteria_congestion,
        hysteria_bbr_profile=body.hysteria_bbr_profile,
        hysteria_disable_udp=body.hysteria_disable_udp,
        hysteria_udp_idle_timeout=body.hysteria_udp_idle_timeout,
        hysteria_masquerade_url=body.hysteria_masquerade_url,
        hysteria_stats_secret=_secrets.token_urlsafe(32),
        hysteria_stats_port=body.hysteria_stats_port,
        hysteria_advanced_json=body.hysteria_advanced_json,
        bandwidth_mbps=float(body.bandwidth_mbps or 0.0),
        hosting_provider=(body.hosting_provider or "").strip(),
        expires_at=_normalise_node_expiry(body.expires_at),
        notification_bot_id=_validate_notification_bot(db, body.notification_bot_id),
    )
    db.add(server)
    db.commit()
    db.refresh(server)

    # Seed with a first client so the user gets a working vless link immediately.
    first = Client(
        server_id=server.id,
        uuid=(
            _secrets.token_urlsafe(24)
            if protocol == PROTOCOL_HYSTERIA2
            else str(uuidlib.uuid4())
        ),
        email=f"{server.name}-user1",
        label=f"{server.name}",
        flow=(
            "xtls-rprx-vision"
            if protocol == PROTOCOL_VLESS
            and transport_supports_flow(new_transport)
            else ""
        ),
    )
    db.add(first)
    db.commit()
    db.refresh(server)

    _provision_all_server_subscriptions_for_server(server, db)

    try:
        _push_config(server, db)
    except AgentError as e:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(e)) from e

    # Fresh pool member (any tier) means existing balancers need to
    # discover it — ``in_pool=True`` covers the legacy primary case
    # but a fallback-tier row has ``in_pool=False`` while still being
    # a valid balancer upstream, so check the resolved tier instead.
    if auto_balance.is_in_auto_balance(server):
        rebuild_balancer_configs(db)

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
    # Short-timeout probe + TTL cache: a dead agent answers in
    # ``HEALTH_TIMEOUT`` seconds at most and subsequent calls inside
    # the window hit the cache. Without this the panel UI froze on
    # the first click into an offline server.
    entry = _get_server_health(s)
    client_count = int(
        db.scalar(
            select(func.count(Client.id)).where(*_visible_client_clauses(s.id))
        )
        or 0
    )
    return _server_to_dict(
        s,
        online=entry.online,
        xray_version=entry.xray_version,
        xray_active=entry.xray_active,
        client_count=client_count,
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
    if is_custom(s):
        allowed = {
            "name", "display_name", "in_pool", "pool_tier", "bandwidth_mbps",
            "tags", "warp_enabled", "warp_domains", "hosting_provider",
            "expires_at", "notification_bot_id",
        }
        forbidden = sorted(set(body.model_fields_set) - allowed)
        if forbidden:
            raise HTTPException(
                status_code=400,
                detail=(
                    "custom node xray parameters are locked; forbidden fields: "
                    + ", ".join(forbidden)
                ),
            )
    if is_hysteria2(s) and "upstream_server_id" in body.model_fields_set:
        raise HTTPException(
            status_code=400,
            detail="Hysteria 2 nodes cannot be converted to Xray chain mode",
        )
    # A balancer is never its own upstream — silently ignore an attempt
    # to flip ``in_pool`` on one instead of 400-ing so older UI builds
    # that always send the full payload don't trip the error.
    if body.in_pool is True and is_balancer(s):
        body.in_pool = None
    # Same guard for the new ``pool_tier`` knob — balancer / front rows
    # are routers, never pool members.
    if body.pool_tier and is_balancer(s):
        body.pool_tier = None
    # Reconcile in_pool / pool_tier when either was sent. Either field
    # can be patched on its own; when both arrive together, the
    # explicit tier wins (it's the more specific knob).
    try:
        new_tier_input = (
            auto_balance.normalise_tier(body.pool_tier)
            if body.pool_tier is not None
            else None
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if new_tier_input is not None:
        # ``in_pool`` is derived from the tier in this branch.
        body.in_pool = new_tier_input == auto_balance.TIER_PRIMARY
    elif body.in_pool is not None:
        # Legacy: in_pool flip implies primary tier on/off.
        if body.in_pool:
            new_tier_input = auto_balance.TIER_PRIMARY
        else:
            current_tier = auto_balance.server_pool_tier(s)
            # Don't kick a fallback row out of its tier when the admin
            # toggles ``in_pool`` off (that would silently demote the
            # row); only clear the tier when it was the primary one.
            if current_tier == auto_balance.TIER_PRIMARY:
                new_tier_input = auto_balance.TIER_NONE
    if (
        new_tier_input in {auto_balance.TIER_PRIMARY, auto_balance.TIER_FALLBACK}
        and bool(getattr(s, "tspu_blocked", False))
    ):
        raise HTTPException(
            status_code=400,
            detail="node IP is marked blocked by cheburcheck; run a clean TSPU check first",
        )
    # Validate / normalise the upstream knob. ``upstream_server_id`` does
    # double duty:
    #   * On a whitelist-front it re-points the chain at a different
    #     foreign exit (``None``/``0`` = unlink → degrade to direct).
    #   * On a standalone it auto-converts the row to whitelist-front
    #     pointing at the picked upstream (so an admin can take a
    #     regular foreign node and turn it into a fallback chain
    #     without re-enrolling). Conversely, sending ``0``/``null`` on
    #     a whitelist-front converts it back to standalone.
    # Balancers never accept an upstream; reject explicitly.
    upstream_field_set = "upstream_server_id" in body.model_fields_set
    if upstream_field_set:
        if is_balancer(s):
            raise HTTPException(
                status_code=400,
                detail="balancer nodes don't support upstream_server_id",
            )
        target = int(body.upstream_server_id or 0)
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
    mode_changed = False
    old_mode: str = (getattr(s, "mode", "") or "standalone") or "standalone"
    old_upstream_id: int | None = None
    changed: list[str] = []
    # Clean list-valued metadata before mutating the ORM row. Enabling WARP
    # against an empty legacy row seeds the requested Google/Gemini defaults.
    if body.tags is not None:
        body.tags = _normalise_server_tags(body.tags)
    effective_warp_enabled = (
        bool(body.warp_enabled)
        if body.warp_enabled is not None
        else bool(getattr(s, "warp_enabled", False))
    )
    if body.warp_domains is not None:
        body.warp_domains = _normalise_server_warp_domains(
            body.warp_domains, enabled=effective_warp_enabled
        )
    elif effective_warp_enabled and not server_warp_domains(s):
        body.warp_domains = list(DEFAULT_WARP_DOMAINS)
    if body.warp_enabled is True:
        if is_hysteria2(s):
            raise HTTPException(
                status_code=400, detail="WARP is not supported on Hysteria 2 nodes"
            )
        _require_active_warp(s)
    if "notification_bot_id" in body.model_fields_set:
        body.notification_bot_id = _validate_notification_bot(
            db, body.notification_bot_id
        )
    # Normalise transport up-front so the loop below can `getattr(body, ...)`
    # uniformly and the audit trail records the cleaned value.
    if body.transport is not None:
        try:
            body.transport = normalise_transport(body.transport)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    if body.transport_path is not None:
        body.transport_path = (body.transport_path or "").strip()
    if is_hysteria2(s):
        def _hy_value(field: str) -> Any:
            value = getattr(body, field, None)
            return getattr(s, field) if value is None else value

        try:
            effective_auth_mode, effective_auth_password = _prepare_hysteria_auth(
                _hy_value("hysteria_auth_mode"),
                _hy_value("hysteria_auth_password"),
            )
            effective_obfs_type, effective_obfs_password = _prepare_hysteria_obfs(
                _hy_value("hysteria_obfs_type"),
                _hy_value("hysteria_obfs_password"),
            )
            # Persist generated secrets when an admin switches a node to a
            # newly-created password/Salamander credential.
            if (
                body.hysteria_auth_mode is not None
                or effective_auth_mode == HYSTERIA_AUTH_PASSWORD
            ):
                body.hysteria_auth_mode = effective_auth_mode
                body.hysteria_auth_password = effective_auth_password
            if body.hysteria_obfs_type is not None:
                body.hysteria_obfs_type = effective_obfs_type
                body.hysteria_obfs_password = effective_obfs_password
            if body.sni is not None:
                body.sni = _validate_sni(body.sni)
            build_hysteria_config(
                port=int(_hy_value("port")),
                listen=str(_hy_value("hysteria_listen") or ""),
                sni=str(_hy_value("sni") or ""),
                tls_mode=str(_hy_value("hysteria_tls_mode") or ""),
                acme_email=str(_hy_value("hysteria_acme_email") or ""),
                cert_path=str(_hy_value("hysteria_cert_path") or ""),
                key_path=str(_hy_value("hysteria_key_path") or ""),
                clients=[],
                auth_mode=effective_auth_mode,
                auth_password=effective_auth_password,
                stats_secret=str(
                    getattr(s, "hysteria_stats_secret", "")
                    or "server-update-validation"
                ),
                stats_port=int(_hy_value("hysteria_stats_port")),
                obfs_type=effective_obfs_type,
                obfs_password=effective_obfs_password,
                up_mbps=int(_hy_value("hysteria_up_mbps") or 0),
                down_mbps=int(_hy_value("hysteria_down_mbps") or 0),
                ignore_client_bandwidth=bool(
                    _hy_value("hysteria_ignore_client_bandwidth")
                ),
                congestion=str(_hy_value("hysteria_congestion") or ""),
                bbr_profile=str(_hy_value("hysteria_bbr_profile") or ""),
                disable_udp=bool(_hy_value("hysteria_disable_udp")),
                udp_idle_timeout_seconds=int(
                    _hy_value("hysteria_udp_idle_timeout")
                ),
                masquerade_url=str(_hy_value("hysteria_masquerade_url") or ""),
                advanced_json=str(_hy_value("hysteria_advanced_json") or ""),
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    endpoint_port = int(getattr(s, "sni_endpoint_port", 9443) or 9443)
    if bool(getattr(s, "sni_endpoint_enabled", False)):
        next_vpn_port = int(body.port or s.port)
        if next_vpn_port == endpoint_port:
            raise HTTPException(
                status_code=409,
                detail=(
                    f"VPN port {next_vpn_port} conflicts with the managed "
                    "SNI endpoint; choose different ports"
                ),
            )
    for field in (
        "name", "display_name", "in_pool", "agent_url", "agent_token",
        "public_host", "port", "sni", "dest",
        "transport", "transport_path", "bandwidth_mbps", "warp_enabled",
        "hosting_provider",
        "hysteria_listen", "hysteria_auth_mode", "hysteria_auth_password",
        "hysteria_tls_mode", "hysteria_acme_email",
        "hysteria_cert_path", "hysteria_key_path", "hysteria_obfs_type",
        "hysteria_obfs_password", "hysteria_up_mbps",
        "hysteria_down_mbps", "hysteria_ignore_client_bandwidth",
        "hysteria_congestion", "hysteria_bbr_profile",
        "hysteria_disable_udp", "hysteria_udp_idle_timeout",
        "hysteria_masquerade_url", "hysteria_stats_port",
        "hysteria_advanced_json",
    ):
        v = getattr(body, field, None)
        if v is None:
            continue
        old = getattr(s, field, None)
        if v == old:
            continue
        if field in {
            "port", "sni", "dest", "transport", "transport_path", "warp_enabled",
            "hysteria_listen", "hysteria_tls_mode", "hysteria_acme_email",
            "hysteria_auth_mode", "hysteria_auth_password",
            "hysteria_cert_path", "hysteria_key_path", "hysteria_obfs_type",
            "hysteria_obfs_password", "hysteria_up_mbps",
            "hysteria_down_mbps", "hysteria_ignore_client_bandwidth",
            "hysteria_congestion", "hysteria_bbr_profile",
            "hysteria_disable_udp", "hysteria_udp_idle_timeout",
            "hysteria_masquerade_url", "hysteria_stats_port",
            "hysteria_advanced_json",
        }:
            dirty_xray = True
        setattr(s, field, v)
        # Redact the token in the audit trail; log only that it changed.
        if field in {"agent_token", "hysteria_obfs_password", "hysteria_auth_password"}:
            changed.append(f"{field}=<rotated>")
        else:
            changed.append(f"{field}={old!r}→{v!r}")
    # ``None`` is a meaningful explicit value here (clearing the lease date),
    # so this patch is handled separately from the generic non-None loop.
    if "expires_at" in body.model_fields_set:
        next_expiry = _normalise_node_expiry(body.expires_at)
        old_expiry = getattr(s, "expires_at", None)
        if next_expiry != old_expiry:
            s.expires_at = next_expiry
            s.expiry_reminder_sent_for = None
            s.expiry_notification_message_id = None
            changed.append(f"expires_at={old_expiry!r}→{next_expiry!r}")
    if "notification_bot_id" in body.model_fields_set:
        next_bot_id = body.notification_bot_id
        old_bot_id = getattr(s, "notification_bot_id", None)
        if next_bot_id != old_bot_id:
            s.notification_bot_id = next_bot_id
            s.expiry_reminder_sent_for = None
            s.expiry_notification_message_id = None
            changed.append(f"notification_bot_id={old_bot_id!r}→{next_bot_id!r}")
    if body.tags is not None:
        encoded_tags = json.dumps(body.tags, ensure_ascii=False)
        if encoded_tags != (getattr(s, "tags", "[]") or "[]"):
            s.tags = encoded_tags
            changed.append(f"tags={body.tags!r}")
    if body.warp_domains is not None:
        encoded_domains = json.dumps(body.warp_domains, ensure_ascii=False)
        if encoded_domains != (getattr(s, "warp_domains", "[]") or "[]"):
            s.warp_domains = encoded_domains
            changed.append(f"warp_domains={len(body.warp_domains)} entries")
            if effective_warp_enabled:
                dirty_xray = True
    # Apply the resolved tier (computed from in_pool / pool_tier above)
    # AFTER the loop so it lands even when only pool_tier was sent.
    if new_tier_input is not None:
        old_tier = (getattr(s, "pool_tier", "") or "")
        if new_tier_input != old_tier:
            s.pool_tier = new_tier_input
            changed.append(f"pool_tier={old_tier!r}→{new_tier_input!r}")
    # Handle upstream_server_id separately: ``None`` is a meaningful
    # value (unlink), so we can't bail on ``v is None`` like the loop
    # above does. Only act when the field was explicitly part of the
    # request payload (model_fields_set tracks that in pydantic v2).
    #
    # Three transitions are possible:
    #   * whitelist-front → whitelist-front (re-point at a new upstream)
    #   * standalone      → whitelist-front (admin attaches an upstream
    #                       to a regular foreign node so it becomes a
    #                       fallback-tier chain)
    #   * whitelist-front → standalone (admin clears the upstream so
    #                       the node serves direct again)
    # The tier knob is left alone in the conversion so admins can keep
    # the fallback flag (or any other) explicitly. ``in_pool`` gets
    # forced off when transitioning into whitelist-front since the
    # balancer's ``pool_upstreams`` query only ever returns standalone
    # rows — leaving the flag set would silently mismatch reality.
    if upstream_field_set:
        new_up = body.upstream_server_id
        old_up = getattr(s, "upstream_server_id", None)
        if new_up != old_up:
            old_upstream_id = old_up
            s.upstream_server_id = new_up
            dirty_xray = True
            upstream_changed = True
            changed.append(f"upstream_server_id={old_up!r}→{new_up!r}")
        # Decide the mode based on the new upstream value, falling
        # through standalone → whitelist-front and back as the chain
        # gets attached / detached.
        new_mode: Optional[str] = None
        if new_up:
            if old_mode != WHITELIST_FRONT_MODE:
                new_mode = WHITELIST_FRONT_MODE
        else:
            if old_mode == WHITELIST_FRONT_MODE:
                new_mode = "standalone"
        if new_mode is not None and new_mode != old_mode:
            s.mode = new_mode
            mode_changed = True
            dirty_xray = True
            changed.append(f"mode={old_mode!r}→{new_mode!r}")
            # Clear the legacy primary-pool flag when a row becomes a
            # whitelist-front. ``pool_upstreams`` does include
            # whitelist-front rows now, but only via their explicit
            # ``pool_tier`` (``fallback`` is the intended tier for
            # chains). ``in_pool=True`` infers ``primary`` for
            # tier-less rows, which would silently keep a freshly
            # converted chain in the *primary* tier — wrong for the
            # admin who attached an upstream specifically to demote
            # the row to fallback duty. The explicit ``pool_tier``
            # value, if any, is preserved above and continues to win.
            if new_mode == WHITELIST_FRONT_MODE and bool(
                getattr(s, "in_pool", False)
            ):
                s.in_pool = False
                changed.append("in_pool=True→False")
    if changed:
        audit_mod.record(
            db, user=user, action="server.update",
            resource_type="server", resource_id=s.id,
            details=", ".join(changed),
        )
    db.commit()
    if dirty_xray:
        try:
            _push_config(
                s,
                db,
                reconcile_warp="warp_enabled" in body.model_fields_set,
            )
        except AgentError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    if bool(getattr(s, "bridge_enabled", False)) and any(
        item.startswith("public_host=") or item.startswith("port=")
        for item in changed
    ):
        try:
            AgentClient(
                s.bridge_agent_url, s.bridge_agent_token, timeout=60
            ).configure_haproxy_bridge(
                bridge_id=f"server-{s.id}",
                listen_port=int(s.bridge_port),
                target_host=s.public_host,
                target_port=int(s.port),
            )
        except AgentError as exc:
            raise HTTPException(
                status_code=400,
                detail=f"server updated but HAProxy bridge refresh failed: {exc}",
            ) from exc
    # If ``in_pool`` just flipped, every balancer's outbound list needs
    # to be rebuilt. This also re-pushes the *new* pool member's own
    # config so the panel-managed ``__balancer__-<id>`` auth client
    # gets registered on its xray before the balancer dials it.
    # ``pool_tier`` flips on their own can change pool membership too
    # (``''`` ↔ ``fallback`` doesn't touch ``in_pool`` since fallback
    # rows live outside the legacy flag — but ``pool_upstreams`` does
    # include them, so the balancer outbound list must be rebuilt).
    # Mode flips (standalone ↔ whitelist-front) also matter — a freshly
    # converted whitelist-front must be removed from every balancer's
    # outbound list, and a freshly demoted standalone must be added back.
    if mode_changed or any(
        c.startswith("in_pool=") or c.startswith("pool_tier=") for c in changed
    ):
        rebuild_balancer_configs(db)
    # When a whitelist-front gets re-pointed (or reverted to standalone),
    # the old upstream still has a stale ``__bypass__-<front_id>`` auth
    # client. Scrub it + re-push the old upstream so xray drops that UUID.
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
                _push_config(old_up, db, remove_emails=[email])
        except AgentError as exc:
            log.warning(
                "post-repoint cleanup on upstream %d failed: %s",
                old_upstream_id, exc,
            )
    visible_count = int(
        db.scalar(
            select(func.count(Client.id)).where(*_visible_client_clauses(s.id))
        )
        or 0
    )
    return _server_to_dict(s, client_count=visible_count)


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
    was_in_pool = auto_balance.is_in_auto_balance(s)
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
                _push_config(up, db, remove_emails=[f"__balancer__-{sid}"])
            except AgentError as exc:
                log.warning(
                    "post-delete push to upstream %d failed: %s", up.id, exc,
                )
    if was_whitelist_front:
        affected_fronts = delete_bypass_auth_clients(db, sid)
        for up in affected_fronts:
            try:
                _push_config(up, db, remove_emails=[f"__bypass__-{sid}"])
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
    include_clients: bool = True,
    client_ids: str = "",
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    # The UI polls this endpoint every 5 s. If the node is dead, the
    # cached verdict from ``/api/servers`` (10 s TTL) lets us skip
    # both the ``sysinfo()`` and ``stats()`` calls — each of which
    # used to hang for up to 15 s on a black-holed agent and serialise
    # the panel's thread pool. We still re-probe via the short
    # ``HEALTH_TIMEOUT`` if there's no cached verdict yet, so the
    # first poll after a node recovers picks it up quickly.
    cached_health = _health_cache_get(s.id)
    sysinfo: dict | None = None
    traffic: dict[str, dict[str, int]] = {}
    online = False
    if cached_health is not None and not cached_health.online:
        # Known-offline: return immediately without hitting the agent.
        # Client traffic totals stay at the last value persisted by
        # the background ``traffic_sync`` loop, which already isolates
        # per-server failures.
        return {
            "online": False,
            "sysinfo": None,
            "clients": (
                [_client_to_dict(c, s) for c in s.clients]
                if include_clients else []
            ),
            "client_live": {},
            "live": _live_entry_to_dict(None, s),
        }
    agent = AgentClient(s.agent_url, s.agent_token, timeout=HEALTH_TIMEOUT)
    try:
        sysinfo = agent.sysinfo()
        online = True
    except Exception:
        sysinfo = None
    # Refresh the cache so /api/servers and other pollers see the
    # current verdict immediately instead of waiting on the previous
    # TTL window. ``stats()`` payloads can be big on busy nodes, so
    # only fetch them when ``sysinfo()`` already confirmed the node
    # is reachable — saves another 15 s timeout on a dead node.
    _health_cache_set(
        s.id,
        online=online,
        xray_version=(
            cached_health.xray_version if cached_health else ""
        ),
        xray_active=(
            cached_health.xray_active if cached_health else False
        ),
    )
    if online and include_clients:
        try:
            traffic = _fmt_stats(
                AgentClient(s.agent_url, s.agent_token).stats(reset=False)
            )
        except Exception:
            traffic = {}

    # Merge traffic into client totals (cumulative — we do not reset here to keep
    # totals accurate on panel restart; full reset handled by a separate endpoint
    # if ever needed). While iterating, track whether any client's active status
    # flipped from "active" to "inactive" so we can re-push the xray config and
    # actually cut off over-limit / expired users.
    #
    # Live snapshot: pull the cached /live entry (the batch poller keeps it
    # fresh) so we can tag each client row with ``online``/``up_bps``/
    # ``down_bps`` and surface headline ``online_clients`` + NIC rate in
    # the detail pane. When the cache is cold we probe once here so a
    # freshly-opened server detail doesn't show zeros for one cycle.
    live_entry = _live_cache_get(s.id) if online else None
    if online and live_entry is None:
        live_entry = _probe_server_live(s, seed=True)
    live_rates: dict[str, dict[str, int]] = (
        live_entry.client_rates if live_entry else {}
    )
    requested_ids: list[int] = []
    for raw_id in (client_ids or "").split(","):
        raw_id = raw_id.strip()
        if raw_id.isdigit():
            requested_ids.append(int(raw_id))
        if len(requested_ids) >= 100:
            break
    client_live: dict[str, dict[str, Any]] = {}
    if requested_ids:
        visible_rows = db.scalars(
            select(Client).where(
                Client.server_id == s.id,
                Client.id.in_(requested_ids),
            )
        ).all()
        for client in visible_rows:
            rate = live_rates.get(client.email, {})
            client_live[str(client.id)] = {
                "online": bool(rate.get("online", False)),
                "up_bps": int(rate.get("up_bps", 0) or 0),
                "down_bps": int(rate.get("down_bps", 0) or 0),
            }

    if not include_clients:
        return {
            "online": online,
            "sysinfo": sysinfo,
            "clients": [],
            "client_live": client_live,
            "live": _live_entry_to_dict(live_entry if online else None, s),
        }

    needs_push = False
    flipped_clients: list[tuple[Client, str]] = []
    clients_out: list[dict] = []
    server_up_delta = 0
    server_down_delta = 0
    for c in s.clients:
        was_active = c.is_active()
        t = traffic.get(c.email)
        if t:
            up_delta, down_delta, _changed = traffic_sync.apply_traffic_counters(
                c, t.get("up", 0), t.get("down", 0)
            )
            server_up_delta += up_delta
            server_down_delta += down_delta
        if was_active and not c.is_active():
            needs_push = True
            flipped_clients.append((c, _client_status(c)))
        cd = _client_to_dict(c, s)
        rate = live_rates.get(c.email)
        if rate:
            cd["online"] = bool(rate.get("online", False))
            cd["up_bps"] = int(rate.get("up_bps", 0) or 0)
            cd["down_bps"] = int(rate.get("down_bps", 0) or 0)
        else:
            cd["online"] = False
            cd["up_bps"] = 0
            cd["down_bps"] = 0
        clients_out.append(cd)
    metrics_sync.record_daily_traffic(
        db, s.id, server_up_delta, server_down_delta
    )
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
        "client_live": client_live,
        # Live block for the detail header. ``available=False`` when the
        # node is offline or the agent predates /live — the UI then hides
        # the live widgets and keeps showing the cumulative counters.
        "live": _live_entry_to_dict(live_entry if online else None, s),
    }


@app.get("/api/servers/{server_id}/security/sessions")
def api_server_security_sessions(
    server_id: int,
    window_seconds: int = Query(default=900, ge=60, le=7200),
    min_events: int = Query(default=1, ge=1, le=100),
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Proxy short-lived anti-sharing evidence from one authenticated node."""
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        payload = AgentClient(
            server.agent_url, server.agent_token, timeout=HEALTH_TIMEOUT
        ).security_sessions(
            window_seconds=window_seconds,
            min_events=min_events,
        )
    except Exception as exc:  # An offline node is expected fleet state.
        # Do not turn an agent timeout into a panel-wide 500.  Callers can use
        # ``available`` to keep notification-only telemetry from healthy
        # nodes while still failing closed for destructive actions.
        return {
            "server_id": server.id,
            "server_name": server.name,
            "supported": True,
            "available": False,
            "clients": [],
            "error": f"{type(exc).__name__}: {exc}"[:500],
        }
    return {
        "server_id": server.id,
        "server_name": server.name,
        "supported": True,
        "available": True,
        **payload,
    }


# ---------- per-server SNI list ----------
#
# Reality's ``serverNames`` is per-inbound, not per-client — but the
# panel exposes it as if it were a server-level resource. The default
# ``server.sni`` is always implicitly in the list and cannot be removed
# here (that's a separate edit on the server form).
@app.get("/api/servers/{server_id}/snis")
def api_list_snis(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    return {"default": s.sni, "snis": server_all_snis(s)}


@app.post("/api/servers/{server_id}/snis", response_model=ServerOut)
def api_add_sni(
    server_id: int,
    body: dict,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if is_custom(s):
        raise HTTPException(status_code=400, detail="custom node SNI list is config-locked")
    raw = body.get("sni") if isinstance(body, dict) else None
    if not raw:
        raise HTTPException(status_code=400, detail="sni is required")
    new_sni = _validate_sni(str(raw))
    if new_sni in server_all_snis(s):
        # Already present — make it a no-op rather than 400 so the
        # client can blindly POST without checking first.
        return _server_to_dict(s)
    _ensure_server_sni(s, new_sni)
    db.commit()
    db.refresh(s)
    try:
        _push_config(s, db)
    except AgentError as e:
        # Roll back the schema change so the panel and xray don't
        # disagree about which SNIs are valid.
        extras = [
            x for x in (s.extra_snis or "").split(",")
            if x.strip() and x.strip() != new_sni
        ]
        s.extra_snis = ",".join(extras)
        db.commit()
        raise HTTPException(status_code=502, detail=str(e)) from e
    audit_mod.record(
        db, user=user, action="server.sni.add",
        resource_type="server", resource_id=s.id,
        details=f"{new_sni} → {s.name}",
    )
    db.commit()
    return _server_to_dict(s)


@app.delete("/api/servers/{server_id}/snis/{sni}", response_model=ServerOut)
def api_delete_sni(
    server_id: int,
    sni: str,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if is_custom(s):
        raise HTTPException(status_code=400, detail="custom node SNI list is config-locked")
    target = (sni or "").strip().lower()
    if not target:
        raise HTTPException(status_code=400, detail="sni is required")
    if target == (s.sni or "").strip().lower():
        raise HTTPException(
            status_code=400,
            detail="cannot remove the default SNI; edit the server to change it",
        )
    extras_in = [x.strip() for x in (s.extra_snis or "").split(",") if x.strip()]
    if target not in extras_in:
        raise HTTPException(status_code=404, detail="sni not registered on this server")
    # Refuse if any client still pins this SNI — admin must repoint
    # or delete those clients first. Saves us from issuing keys whose
    # vless:// link points at a serverName the inbound no longer
    # accepts.
    pinned = db.scalar(
        select(func.count())
        .select_from(Client)
        .where(Client.server_id == s.id, Client.sni == target)
    )
    if pinned:
        raise HTTPException(
            status_code=400,
            detail=f"cannot remove: {pinned} client(s) still pinned to this SNI",
        )
    s.extra_snis = ",".join(x for x in extras_in if x != target)
    db.commit()
    db.refresh(s)
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    audit_mod.record(
        db, user=user, action="server.sni.delete",
        resource_type="server", resource_id=s.id,
        details=f"{target} ✕ {s.name}",
    )
    db.commit()
    return _server_to_dict(s)


@app.post(
    "/api/servers/{server_id}/sni-endpoint",
    response_model=ServerOut,
)
def api_provision_sni_endpoint(
    server_id: int,
    body: SniEndpointProvisionIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Provision the node's own HTTPS fallback and attach it to Reality."""
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400,
            detail=(
                "Hysteria 2 terminates its own TLS; the Reality SNI endpoint "
                "is available only for VLESS+Reality nodes"
            ),
        )
    if is_custom(s):
        raise HTTPException(
            status_code=400,
            detail="custom nodes keep their Reality destination externally managed",
        )
    domain = _validate_sni(body.domain)
    email = (body.email or "").strip()
    if not email or "@" not in email:
        raise HTTPException(status_code=400, detail="a valid ACME email is required")
    endpoint_port = int(body.port)
    if endpoint_port == int(s.port):
        raise HTTPException(
            status_code=409,
            detail=(
                f"port {endpoint_port} is already the VPN port; the SNI "
                "endpoint must use a different internal port"
            ),
        )
    try:
        result = AgentClient(s.agent_url, s.agent_token).provision_sni_endpoint(
            domain=domain,
            email=email,
            port=endpoint_port,
            vpn_port=int(s.port),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"SNI endpoint provisioning failed: {exc}"
        ) from exc

    s.sni_endpoint_enabled = True
    s.sni_endpoint_domain = domain
    s.sni_endpoint_email = email
    s.sni_endpoint_port = endpoint_port
    s.sni = domain
    s.dest = str(result.get("dest") or f"127.0.0.1:{endpoint_port}")
    try:
        _push_config(s, db)
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        raise HTTPException(
            status_code=400,
            detail=f"SNI endpoint is online but Xray config push failed: {exc}",
        ) from exc
    audit_mod.record(
        db,
        user=user,
        action="server.sni_endpoint.provision",
        resource_type="server",
        resource_id=s.id,
        details=f"{domain} → {s.dest}; vpn_port={s.port}",
    )
    db.commit()
    db.refresh(s)
    _invalidate_server_health(s.id)
    return _server_to_dict(s)


# ---------- clients ----------
@app.get("/api/servers/{server_id}/clients/page")
def api_list_clients_page(
    server_id: int,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=10, le=100),
    q: str = Query(default="", max_length=128),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    del user
    server = db.get(Server, server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="server not found")
    clauses = _visible_client_clauses(server.id)
    search = (q or "").strip()
    if search:
        pattern = f"%{search}%"
        clauses.append(
            Client.email.ilike(pattern)
            | Client.label.ilike(pattern)
            | Client.uuid.ilike(pattern)
        )
    total = int(
        db.scalar(select(func.count(Client.id)).where(*clauses)) or 0
    )
    rows = db.scalars(
        select(Client)
        .where(*clauses)
        .order_by(Client.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    ).all()
    live_entry = _live_cache_get(server.id)
    rates = live_entry.client_rates if live_entry else {}
    items: list[dict[str, Any]] = []
    for client in rows:
        item = _client_to_dict(client, server)
        rate = rates.get(client.email, {})
        item["online"] = bool(rate.get("online", False))
        item["up_bps"] = int(rate.get("up_bps", 0) or 0)
        item["down_bps"] = int(rate.get("down_bps", 0) or 0)
        items.append(item)
    pages = max(1, (total + page_size - 1) // page_size)
    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": pages,
    }


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
    skip_push: bool = False,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Create a Client on ``server_id``.

    ``skip_push`` lets a caller batch many client mutations and trigger
    a single ``_push_config`` at the end via
    ``POST /api/servers/{id}/push``. Regular Xray structural pushes may
    restart the core, so batching still matters there. Hysteria 2 auth-only
    changes are delivered to the agent's local HTTP authenticator and do not
    restart or interrupt the Hysteria service.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if db.scalar(
        select(func.count())
        .select_from(Client)
        .where(Client.server_id == s.id, Client.email == body.email)
    ):
        raise HTTPException(status_code=400, detail="email already exists on this server")
    if is_custom(s):
        try:
            if body.email in custom_inbound_client_emails(s):
                raise HTTPException(
                    status_code=400,
                    detail="email already exists in the external custom config",
                )
        except AgentError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    # Per-client SNI: if the admin requested a specific one, register
    # it on the server (auto-extending ``extra_snis`` if it's new) and
    # pin the client. Empty / null ⇒ inherit server.sni.
    pinned_sni: str | None = None
    if is_hysteria2(s) and body.sni is not None and body.sni.strip():
        raise HTTPException(
            status_code=400,
            detail="Hysteria 2 uses the node TLS SNI; per-client SNI is unsupported",
        )
    if not is_hysteria2(s) and body.sni is not None and body.sni.strip():
        pinned_sni = _validate_sni(body.sni)
        _ensure_server_sni(s, pinned_sni)

    client = Client(
        server_id=s.id,
        uuid=(
            _secrets.token_urlsafe(24)
            if is_hysteria2(s)
            else str(uuidlib.uuid4())
        ),
        email=body.email,
        label=body.label or body.email,
        flow=(
            (body.flow or "xtls-rprx-vision")
            if not is_hysteria2(s)
            and transport_supports_flow(server_transport(s))
            else ""
        ),
        sni=pinned_sni,
        data_limit_bytes=body.data_limit_bytes,
        expires_at=body.expires_at,
    )
    db.add(client)
    db.commit()
    db.refresh(s)

    if not skip_push:
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
        details=f"{body.email} @ {s.name}" + (" (skip_push)" if skip_push else ""),
    )
    db.commit()
    return _client_to_dict(client, s)


@app.patch("/api/servers/{server_id}/clients/{client_id}", response_model=ClientOut)
def api_update_client(
    server_id: int,
    client_id: int,
    body: ClientUpdateIn,
    skip_push: bool = False,
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
    if "sni" in fields:
        if is_hysteria2(s):
            raise HTTPException(
                status_code=400,
                detail="Hysteria 2 does not support per-client SNI",
            )
        # ``sni: ""`` clears the pin (revert to server default);
        # non-empty registers + pins exactly like client-create does.
        raw = (fields["sni"] or "").strip()
        if not raw:
            c.sni = None
        else:
            new_sni = _validate_sni(raw)
            _ensure_server_sni(s, new_sni)
            c.sni = new_sni
    db.commit()
    db.refresh(s)

    # Re-push config — an active/inactive flip should reach xray immediately.
    # ``skip_push=true`` lets a batch caller defer to a single end-of-batch
    # push via ``POST /api/servers/{id}/push`` (avoids N xray restarts).
    if not skip_push:
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
    skip_push: bool = False,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Delete a Client. ``skip_push=true`` skips the per-call config push.

    Each push triggers ``systemctl restart xray`` on the node (~10 s of
    dropped UDP for active users), so bulk callers (e.g. expiring N
    subscriptions at once) should pass ``skip_push=true`` and then call
    ``POST /api/servers/{id}/push`` once at the end.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    c = db.get(Client, client_id)
    if c is None or c.server_id != s.id:
        raise HTTPException(status_code=404, detail="client not found")
    deleted_email = c.email
    deleted_id = c.id
    if is_custom(s):
        try:
            _push_config(s, db, remove_emails=[deleted_email])
        except AgentError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    db.delete(c)
    db.commit()
    db.refresh(s)

    if not skip_push and not is_custom(s):
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
        details=f"{deleted_email} @ {s.name}" + (" (skip_push)" if skip_push else ""),
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
    if is_custom(s):
        try:
            existing.update(custom_inbound_client_emails(s))
        except AgentError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    created: list[Client] = []
    eff_flow = (
        (body.flow or "xtls-rprx-vision")
        if not is_hysteria2(s)
        and transport_supports_flow(server_transport(s))
        else ""
    )
    for i in range(1, body.count + 1):
        email = f"{body.email_prefix}-{i}"
        if email in existing:
            continue
        c = Client(
            server_id=s.id,
            uuid=(
                _secrets.token_urlsafe(24)
                if is_hysteria2(s)
                else str(uuidlib.uuid4())
            ),
            email=email,
            label=body.label or email,
            flow=eff_flow,
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
    if is_custom(s) and rows:
        try:
            _push_config(s, db, remove_emails=[client.email for client in rows])
        except AgentError as e:
            raise HTTPException(status_code=400, detail=str(e)) from e
    for c in rows:
        db.delete(c)
    db.commit()
    db.refresh(s)
    if not is_custom(s):
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


@app.post("/api/servers/{server_id}/push")
def api_server_push(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Force a single ``_push_config`` for ``server_id``.

    Pairs with ``skip_push=true`` on the client CRUD endpoints: a bulk
    caller can issue many client mutations cheaply (DB-only) and then
    flush them to xray with one push at the end. Idempotent — calling
    on an unchanged server still works (xray reloads the same config),
    but pointless if you didn't actually mutate anything because every
    push restarts xray on the node.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    audit_mod.record(
        db,
        user=user,
        action="server.push",
        resource_type="server",
        resource_id=s.id,
        details=f"manual push @ {s.name}",
    )
    db.commit()
    # Return the freshly rendered links as well. This is useful for API
    # callers that push after a bridge was enabled: links use the RU listener
    # while ``server.public_host`` remains the EU target for HAProxy.
    server_payload = _server_to_dict(s)
    client_rows = [
        _client_to_dict(c, s) for c in s.clients if not is_service_client(c)
    ]
    return {
        "ok": True,
        "server": server_payload,
        "client_endpoint": server_payload["client_endpoint"],
        "clients": client_rows,
        "links": [row["connection_link"] for row in client_rows],
    }


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
        agent = AgentClient(s.agent_url, s.agent_token)
        result = (
            agent.hysteria_action(action)
            if is_hysteria2(s)
            else agent.xray_action(action)
        )
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e
    # xray restart/start/stop flips ``xray_active`` — drop the cached
    # entry so the next /api/servers poll re-probes and shows the
    # new state right away instead of waiting on the 10 s TTL.
    _invalidate_server_health(s.id)
    return result


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
        agent = AgentClient(s.agent_url, s.agent_token)
        logs = (
            agent.hysteria_logs(lines=lines)
            if is_hysteria2(s)
            else agent.xray_logs(lines=lines)
        )
        return {"lines": logs}
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
    # Node will drop offline within a few seconds — drop the cached
    # ``online=True`` so the UI flips to "offline" on the next poll.
    _invalidate_server_health(s.id)
    audit_mod.record(
        db, user=user, action="server.reboot",
        resource_type="server", resource_id=s.id, details=f"{s.name} delay={delay}s",
    )
    db.commit()
    return result


@app.get("/api/servers/{server_id}/version")
def api_server_version(
    server_id: int,
    user: User = Depends(current_user),  # noqa: ARG001 — auth gate
    db: Session = Depends(get_db),
) -> dict:
    """Return the xnpanel version snapshot from the node's agent."""
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        return AgentClient(s.agent_url, s.agent_token).system_version()
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e


@app.post("/api/servers/{server_id}/upgrade")
def api_server_upgrade(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Trigger ``xnpanel update --force`` on a single node via its agent."""
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        result = AgentClient(s.agent_url, s.agent_token).system_upgrade()
    except AgentError as e:
        raise HTTPException(status_code=502, detail=str(e)) from e
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"agent unreachable: {e}") from e
    # xray-agent.service restarts mid-update — the next health probe
    # transiently fails, but we still want to *re-probe* (not serve a
    # stale ``online=True``) so the UI surfaces the brief gap.
    _invalidate_server_health(s.id)
    audit_mod.record(
        db, user=user, action="server.upgrade",
        resource_type="server", resource_id=s.id, details=s.name,
    )
    db.commit()
    return result


# ---------------------------------------------------------------------------
# Bulk-upgrade job tracker.
#
# Hitting ``system_upgrade`` on every node sequentially used to block the
# request thread for the entire batch — N × httpx_timeout in the worst
# case (e.g. one unreachable node burns 15s before we even try the next).
# The panel UI rendered a single "Обновление…" spinner during all of
# that with zero feedback per node, and the request that hosted the call
# would die mid-batch the moment the panel-host's own agent restarted
# xray-panel.service.
#
# We now run a durable, strictly sequential queue.  Only one node is touched
# at a time; a node is retried until its update is confirmed or the admin
# cancels the job.  This is deliberately conservative: a failed agent must
# not leave the rest of the fleet half-updated, and the panel host is still
# placed last because its service restart interrupts the HTTP worker.
# The frontend polls ``GET /api/admin/upgrade-jobs/{job_id}`` every
# second to render a live progress bar.
# ---------------------------------------------------------------------------

# job_id -> {created_at, finished_at, started_at, total, done, nodes: [...]}
_upgrade_jobs: dict[str, dict[str, Any]] = {}
_upgrade_jobs_lock = threading.Lock()
_upgrade_worker_ids: set[str] = set()
# A persisted job is recovered from the first status poll after a panel
# restart.  Recovery must be single-flight: otherwise every one-second poll
# can start its own DB/agent reconciliation and exhaust SQLite's connection
# pool before the browser receives a response.
_upgrade_recovery_ids: set[str] = set()
_UPGRADE_JOB_DIR = Path(
    os.environ.get(
        "PANEL_UPGRADE_JOB_DIR",
        "/var/lib/xray-panel/upgrade-jobs",
    )
)
# Jobs are kept for this long after completion so a slow user can still
# read the per-node results. Older jobs are pruned on every new request.
_UPGRADE_JOB_TTL_SECONDS = 3600
# Cap parallel non-local agent calls — most batches are < 20 nodes and
# fan-out beyond that mostly just bloats panel host CPU.
# Retry delay is long enough not to hammer an unavailable agent, while still
# making a transient network flap self-healing.  A finite limit is important:
# one dead node must never hold the rest of the fleet queue forever.
_UPGRADE_RETRY_BACKOFF_SECONDS = 10.0
_UPGRADE_MAX_ATTEMPTS = 3
# Version/health probes may still fan out; only the mutating upgrade queue is
# sequential.
_UPGRADE_JOB_MAX_WORKERS = 8

# After ``system_upgrade`` returns ``scheduled=true`` the agent has only
# *queued* the upgrade. The actual ``xnpanel update --force`` runs in a
# detached shell that may fail silently (git clone blocked, branch gone,
# disk full, …). We verify by polling ``/system/version`` until the
# reported installed SHA changes — or until we give up. The timeout is
# generous: a slow node on bad uplink can take 30-60s just for
# ``git clone --depth 1``, plus pip install + service restart.
_UPGRADE_VERIFY_TIMEOUT_SECONDS = 180.0
_UPGRADE_VERIFY_POLL_INTERVAL = 3.0


def _upgrade_job_path(job_id: str) -> Path | None:
    if not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", job_id or ""):
        return None
    return _UPGRADE_JOB_DIR / f"{job_id}.json"


def _persist_upgrade_job_locked(job: dict[str, Any]) -> None:
    """Persist a job while ``_upgrade_jobs_lock`` is held.

    The panel host updates itself last and restarts xray-panel.service.  A
    disk snapshot lets the replacement process resume status reporting
    instead of returning 404 and leaving the browser in an endless spinner.
    """
    path = _upgrade_job_path(str(job.get("id", "")))
    if path is None:
        return
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(f"{path.name}.tmp-{os.getpid()}")
        tmp.write_text(json.dumps(job, ensure_ascii=False, separators=(",", ":")))
        os.replace(tmp, path)
    except Exception as exc:  # noqa: BLE001
        log.warning("could not persist upgrade job %s: %s", job.get("id"), exc)


def _load_persisted_upgrade_job(job_id: str) -> dict[str, Any] | None:
    path = _upgrade_job_path(job_id)
    if path is None:
        return None
    try:
        value = json.loads(path.read_text())
    except (FileNotFoundError, ValueError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _upgrade_is_local(agent_url: str) -> bool:
    """Is this agent_url the panel host's own agent?

    Upgrading the local agent restarts xray-panel.service, which kills
    every in-flight request — so we run it dead last after all remote
    nodes have already been kicked.
    """
    url = (agent_url or "").lower()
    return "127.0.0.1" in url or "localhost" in url


def _prune_old_upgrade_jobs() -> None:
    cutoff = time.time() - _UPGRADE_JOB_TTL_SECONDS
    with _upgrade_jobs_lock:
        for jid in list(_upgrade_jobs):
            created = _upgrade_jobs[jid].get("created_at", 0.0)
            if created < cutoff:
                _upgrade_jobs.pop(jid, None)
        try:
            for path in _UPGRADE_JOB_DIR.glob("*.json"):
                if path.stat().st_mtime < cutoff:
                    path.unlink(missing_ok=True)
        except (FileNotFoundError, OSError):
            pass


def _set_upgrade_node_status(
    job_id: str, server_id: int, **fields: Any
) -> None:
    """Atomically update one node's row in the job record."""
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        if job is None:
            return
        for node in job["nodes"]:
            if node["server_id"] == server_id:
                node.update(fields)
                break
        _persist_upgrade_job_locked(job)


def _probe_installed_sha(
    agent_url: str, agent_token: str
) -> tuple[str, str]:
    """Return ``(installed_sha, latest_sha)`` from the agent's version cache.

    Returns ``("", "")`` if the call fails — caller decides what to do.
    """
    try:
        r = AgentClient(agent_url, agent_token).system_version()
    except Exception:  # noqa: BLE001
        return "", ""
    return (
        str(r.get("installed", "") or ""),
        str(r.get("latest", "") or ""),
    )


def _upgrade_cancel_requested(job_id: str) -> bool:
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        return bool(job and job.get("cancel_requested"))


def _upgrade_wait_or_cancel(job_id: str, seconds: float) -> bool:
    """Wait in short slices so cancellation is observed quickly."""
    deadline = time.monotonic() + max(0.0, seconds)
    while time.monotonic() < deadline:
        if _upgrade_cancel_requested(job_id):
            return True
        time.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
    return _upgrade_cancel_requested(job_id)


def _run_upgrade_node(
    job_id: str, server_id: int, name: str, agent_url: str, agent_token: str
) -> dict[str, Any]:
    """Update one node, retrying a few times before yielding the queue."""
    attempt = 0
    last_message = ""
    while (
        attempt < _UPGRADE_MAX_ATTEMPTS
        and not _upgrade_cancel_requested(job_id)
    ):
        attempt += 1
        _set_upgrade_node_status(
            job_id, server_id, status="running", attempt=attempt,
            scheduled=False, started_at=time.time(), finished_at=None,
            message=f"попытка {attempt}: запускаю обновление",
        )
        before_sha, before_latest = _probe_installed_sha(agent_url, agent_token)
        _set_upgrade_node_status(
            job_id, server_id, before_sha=before_sha, latest_sha=before_latest,
            message=f"попытка {attempt}: отправляю команду агенту",
        )

        scheduled = False
        agent_job_id = ""
        try:
            result = AgentClient(agent_url, agent_token).system_upgrade()
            scheduled = bool(result.get("ok")) and bool(result.get("scheduled"))
            agent_job_id = str(result.get("job_id", "") or "")
            last_message = str(result.get("message", "") or "")
            if not scheduled and not last_message:
                last_message = "агент не подтвердил запуск обновления"
        except AgentError as exc:
            last_message = str(exc)
        except Exception as exc:  # noqa: BLE001
            last_message = f"agent unreachable: {exc}"

        if scheduled:
            _set_upgrade_node_status(
                job_id, server_id, status="verifying", scheduled=True,
                agent_job_id=agent_job_id,
                message=f"попытка {attempt}: проверяю результат",
            )
            deadline = time.monotonic() + _UPGRADE_VERIFY_TIMEOUT_SECONDS
            after_sha = ""
            while time.monotonic() < deadline:
                if _upgrade_wait_or_cancel(job_id, _UPGRADE_VERIFY_POLL_INTERVAL):
                    break
                try:
                    upgrade_status = AgentClient(
                        agent_url, agent_token
                    ).system_upgrade_status()
                except Exception:  # noqa: BLE001 — old agents may return 404
                    upgrade_status = {}
                status_job_id = str(upgrade_status.get("job_id", "") or "")
                status_matches = (
                    not agent_job_id or not status_job_id
                    or status_job_id == agent_job_id
                )
                if status_matches and upgrade_status.get("status") == "failed":
                    last_message = str(
                        upgrade_status.get("message") or "xnpanel update failed"
                    )
                    break
                installed, latest = _probe_installed_sha(agent_url, agent_token)
                if status_matches and upgrade_status.get("status") == "ok":
                    after_sha = installed or before_sha
                    break
                if installed and installed != before_sha:
                    after_sha = installed
                    break
                if installed and latest and installed == latest:
                    after_sha = installed
                    break
            if after_sha:
                _set_upgrade_node_status(
                    job_id, server_id, status="ok", ok=True, scheduled=True,
                    message="обновление подтверждено", after_sha=after_sha,
                    finished_at=time.time(),
                )
                return {
                    "server_id": server_id, "name": name, "ok": True,
                    "scheduled": True, "status": "ok", "message": "",
                    "before_sha": before_sha, "after_sha": after_sha,
                }
            if not last_message:
                last_message = (
                    f"версия не подтвердилась за {int(_UPGRADE_VERIFY_TIMEOUT_SECONDS)}с"
                )
        if attempt >= _UPGRADE_MAX_ATTEMPTS:
            final_message = (
                f"{last_message or 'обновление не подтверждено'}; "
                f"исчерпано попыток: {_UPGRADE_MAX_ATTEMPTS}"
            )
            _set_upgrade_node_status(
                job_id, server_id, status="timeout", ok=False,
                scheduled=scheduled, last_error=final_message,
                message=final_message, finished_at=time.time(),
            )
            return {
                "server_id": server_id, "name": name, "ok": False,
                "scheduled": scheduled, "status": "timeout",
                "message": final_message, "before_sha": before_sha,
                "after_sha": "",
            }
        _set_upgrade_node_status(
            job_id, server_id, status="retrying", ok=False,
            scheduled=scheduled, last_error=last_message,
            message=(f"{last_message}; повтор через "
                     f"{int(_UPGRADE_RETRY_BACKOFF_SECONDS)}с"),
        )
        if _upgrade_wait_or_cancel(job_id, _UPGRADE_RETRY_BACKOFF_SECONDS):
            break

    _set_upgrade_node_status(
        job_id, server_id, status="cancelled", ok=False,
        message="отменено администратором", finished_at=time.time(),
    )
    return {
        "server_id": server_id, "name": name, "ok": False,
        "scheduled": False, "status": "cancelled",
        "message": "отменено администратором", "before_sha": "", "after_sha": "",
    }


def _upgrade_job_worker(
    job_id: str, plan: list[dict[str, Any]]
) -> None:
    """Drive the fleet queue strictly one node at a time."""
    try:
        with _upgrade_jobs_lock:
            job = _upgrade_jobs.get(job_id)
            if job is None:
                return
            job["started_at"] = time.time()
            _persist_upgrade_job_locked(job)

        for index, p in enumerate(plan):
            if _upgrade_cancel_requested(job_id):
                break
            _set_upgrade_job_fields(
                job_id, current_index=index,
                current_server_id=p["server_id"],
            )
            _set_upgrade_node_status(
                job_id, p["server_id"], queue_position=index + 1,
                message="нода в очереди",
            )
            try:
                _run_upgrade_node(
                    job_id, p["server_id"], p["name"],
                    p["agent_url"], p["agent_token"],
                )
            except Exception as exc:  # noqa: BLE001 — one node must not stop the queue
                message = f"внутренняя ошибка worker: {exc}"
                log.exception(
                    "bulk upgrade failed for server %s in job %s",
                    p["server_id"], job_id,
                )
                _set_upgrade_node_status(
                    job_id, p["server_id"], status="error", ok=False,
                    last_error=message, message=message,
                    finished_at=time.time(),
                )
    finally:
        with _upgrade_jobs_lock:
            job = _upgrade_jobs.get(job_id)
            if job is not None:
                job["done"] = True
                job["finished_at"] = time.time()
                _persist_upgrade_job_locked(job)
        _upgrade_worker_ids.discard(job_id)


def _set_upgrade_job_fields(job_id: str, **fields: Any) -> None:
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        if job is None:
            return
        job.update(fields)
        _persist_upgrade_job_locked(job)


def _launch_upgrade_worker(job_id: str, plan: list[dict[str, Any]]) -> bool:
    """Start exactly one worker for a job, including after panel restart."""
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        if job is None or job.get("done") or job.get("cancel_requested"):
            return False
        if job_id in _upgrade_worker_ids:
            return False
        _upgrade_worker_ids.add(job_id)
    t = threading.Thread(
        target=_upgrade_job_worker,
        args=(job_id, plan),
        name=f"upgrade-job-{job_id}", daemon=True,
    )
    t.start()
    return True


def _start_upgrade_job(servers: list[Server]) -> str:
    """Create and kick off an upgrade job. Returns its ``job_id``."""
    _prune_old_upgrade_jobs()

    # Snapshot DB rows up front — the worker thread can't safely touch
    # the request-scoped SQLAlchemy session.
    plan: list[dict[str, Any]] = []
    nodes: list[dict[str, Any]] = []
    for s in servers:
        is_local = _upgrade_is_local(s.agent_url or "")
        plan.append({
            "server_id": s.id,
            "name": s.name,
            "agent_url": s.agent_url or "",
            "agent_token": s.agent_token or "",
            "is_local": is_local,
        })
        nodes.append({
            "server_id": s.id,
            "name": s.name,
            "is_local": is_local,
            "status": "pending",
            "ok": False,
            "scheduled": False,
            "message": "",
            "before_sha": "",
            "after_sha": "",
            "latest_sha": "",
            "agent_job_id": "",
            "attempt": 0,
            "queue_position": len(nodes) + 1,
            "finished_at": None,
        })

    job_id = _secrets.token_urlsafe(12)
    with _upgrade_jobs_lock:
        _upgrade_jobs[job_id] = {
            "id": job_id,
            "created_at": time.time(),
            "started_at": None,
            "finished_at": None,
            "total": len(nodes),
            "done": False,
            "cancel_requested": False,
            "current_index": None,
            "current_server_id": None,
            "nodes": nodes,
        }
        _persist_upgrade_job_locked(_upgrade_jobs[job_id])
    _launch_upgrade_worker(job_id, plan)
    return job_id


def _snapshot_upgrade_job(job_id: str) -> dict[str, Any] | None:
    """Return a deep-ish copy of the job for the API response."""
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        if job is None:
            job = _load_persisted_upgrade_job(job_id)
            if job is not None:
                _upgrade_jobs[job_id] = job
        if job is None:
            return None
        nodes = [dict(n) for n in job["nodes"]]
        return {
            "id": job["id"],
            "created_at": job["created_at"],
            "started_at": job["started_at"],
            "finished_at": job["finished_at"],
            "total": job["total"],
            "done": job["done"],
            "cancel_requested": bool(job.get("cancel_requested")),
            "current_index": job.get("current_index"),
            "current_server_id": job.get("current_server_id"),
            "nodes": nodes,
            "completed": sum(
                1 for n in nodes
                if n["status"] in ("ok", "error", "timeout", "cancelled")
            ),
            "succeeded": sum(1 for n in nodes if n["status"] == "ok"),
            "failed": sum(1 for n in nodes if n["status"] == "error"),
            "timed_out": sum(1 for n in nodes if n["status"] == "timeout"),
            "cancelled": sum(1 for n in nodes if n["status"] == "cancelled"),
            "running": sum(
                1 for n in nodes
                if n["status"] in ("running", "verifying", "retrying")
            ),
        }


def _recover_upgrade_job(job_id: str, db: Session) -> None:
    """Resume a persisted job without blocking the HTTP status endpoint.

    Older code reconciled every pending node by making several sequential
    agent requests while the request-scoped SQLAlchemy session was open.  A
    browser polling once per second could therefore occupy every SQLite pool
    connection.  Recovery now only snapshots the server rows (fast local DB
    reads) and lets the normal background worker perform all network work.
    Re-running a pending node is safe because the agent itself de-duplicates a
    currently running update.
    """
    with _upgrade_jobs_lock:
        if (
            job_id in _upgrade_worker_ids
            or job_id in _upgrade_recovery_ids
        ):
            return
        _upgrade_recovery_ids.add(job_id)
    try:
        snap = _snapshot_upgrade_job(job_id)
        if snap is None or snap.get("done"):
            return
        terminal = {"ok", "error", "timeout", "cancelled"}
        plan: list[dict[str, Any]] = []
        for node in snap.get("nodes", []):
            if node.get("status") in terminal:
                continue
            server = db.get(Server, node.get("server_id"))
            if server is None:
                _set_upgrade_node_status(
                    job_id,
                    int(node.get("server_id") or 0),
                    status="error",
                    ok=False,
                    message="server was removed while the upgrade was running",
                    finished_at=time.time(),
                )
                continue
            plan.append({
                "server_id": server.id,
                "name": server.name,
                "agent_url": server.agent_url or "",
                "agent_token": server.agent_token or "",
                "is_local": _upgrade_is_local(server.agent_url or ""),
            })
        with _upgrade_jobs_lock:
            job = _upgrade_jobs.get(job_id)
            if job is None:
                return
            if job.get("cancel_requested"):
                for node in job.get("nodes", []):
                    if node.get("status") not in terminal:
                        node.update({
                            "status": "cancelled", "ok": False,
                            "message": "отменено администратором",
                            "finished_at": time.time(),
                        })
                job["done"] = True
                job["finished_at"] = job.get("finished_at") or time.time()
                _persist_upgrade_job_locked(job)
                return
            if all(n.get("status") in terminal for n in job.get("nodes", [])):
                job["done"] = True
                job["finished_at"] = job.get("finished_at") or time.time()
                _persist_upgrade_job_locked(job)
                return
        if plan:
            _launch_upgrade_worker(job_id, plan)
    finally:
        with _upgrade_jobs_lock:
            _upgrade_recovery_ids.discard(job_id)


@app.post("/api/admin/upgrade-jobs/{job_id}/cancel")
def api_admin_upgrade_jobs_cancel(
    job_id: str,
    user: User = Depends(current_user),  # noqa: ARG001 - auth gate
) -> dict:
    """Request a cooperative cancellation of a running upgrade queue."""
    with _upgrade_jobs_lock:
        job = _upgrade_jobs.get(job_id)
        if job is None:
            job = _load_persisted_upgrade_job(job_id)
            if job is not None:
                _upgrade_jobs[job_id] = job
        if job is None:
            raise HTTPException(status_code=404, detail="upgrade job not found")
        already_done = bool(job.get("done"))
        if not already_done:
            job["cancel_requested"] = True
            job["cancelled_at"] = time.time()
            job["message"] = "отмена запрошена администратором"
            _persist_upgrade_job_locked(job)
    return _snapshot_upgrade_job(job_id) or {
        "id": job_id, "cancel_requested": True, "done": already_done,
    }


def _load_servers_for_upgrade(db: Session) -> list[Server]:
    """Servers ordered the way the batcher wants — local last."""
    servers = list(db.scalars(select(Server).order_by(Server.id)).all())
    servers.sort(
        key=lambda s: (1 if _upgrade_is_local(s.agent_url or "") else 0, s.id)
    )
    return servers


@app.get("/api/admin/update-status")
def api_admin_update_status(
    user: User = Depends(current_user),  # noqa: ARG001 - auth gate
    db: Session = Depends(get_db),
) -> dict:
    """Return a fleet-wide update snapshot for the post-login banner.

    The local (panel-host) agent performs a fresh, bounded upstream check;
    remote nodes use their timer-populated cache so opening the panel does not
    generate one GitHub request per server.
    """
    rows = [
        {
            "server_id": s.id,
            "name": s.name,
            "agent_url": s.agent_url,
            "agent_token": s.agent_token,
            "is_local": _upgrade_is_local(s.agent_url or ""),
        }
        for s in db.scalars(select(Server).order_by(Server.id)).all()
    ]

    def probe(row: dict[str, Any]) -> dict[str, Any]:
        out = {
            "server_id": row["server_id"],
            "name": row["name"],
            "is_local": row["is_local"],
            "installed": "",
            "latest": "",
            "status": "unknown",
            "checked_at": "",
            "error": "",
        }
        try:
            version = AgentClient(
                row["agent_url"],
                row["agent_token"],
                timeout=25.0 if row["is_local"] else HEALTH_TIMEOUT,
            ).system_version(refresh=bool(row["is_local"]))
            for key in ("installed", "latest", "status", "checked_at"):
                out[key] = str(version.get(key, "") or "")
        except Exception as exc:  # noqa: BLE001
            out["error"] = str(exc)
        return out

    nodes: list[dict[str, Any]] = []
    if rows:
        with ThreadPoolExecutor(
            max_workers=min(_UPGRADE_JOB_MAX_WORKERS, len(rows))
        ) as pool:
            nodes = list(pool.map(probe, rows))
    available = [n for n in nodes if n["status"] == "available"]
    return {
        "available": bool(available),
        "available_count": len(available),
        "panel_update_available": any(
            n["is_local"] and n["status"] == "available" for n in nodes
        ),
        "nodes": nodes,
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


@app.post("/api/admin/upgrade-jobs")
def api_admin_upgrade_jobs_start(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Start a bulk upgrade job in the background. Returns immediately.

    Poll ``GET /api/admin/upgrade-jobs/{job_id}`` for per-node progress.
    """
    servers = _load_servers_for_upgrade(db)
    job_id = _start_upgrade_job(servers)
    audit_mod.record(
        db, user=user, action="admin.upgrade-all.start",
        resource_type="server", resource_id=None,
        details=f"job_id={job_id}; total={len(servers)}",
    )
    db.commit()
    snap = _snapshot_upgrade_job(job_id) or {}
    return {"job_id": job_id, **snap}


@app.get("/api/admin/upgrade-jobs/{job_id}")
def api_admin_upgrade_jobs_get(
    job_id: str,
    user: User = Depends(current_user),  # noqa: ARG001  (auth-only)
    db: Session = Depends(get_db),
) -> dict:
    _recover_upgrade_job(job_id, db)
    snap = _snapshot_upgrade_job(job_id)
    if snap is None:
        raise HTTPException(status_code=404, detail="upgrade job not found")
    return snap


@app.post("/api/admin/upgrade-all")
def api_admin_upgrade_all(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Legacy synchronous bulk-upgrade endpoint.

    Kept for any external scripts that may still call it. The panel UI
    uses ``/api/admin/upgrade-jobs`` for live progress instead. The
    payload shape (``ok`` / ``total`` / ``results``) is preserved.
    """
    servers = _load_servers_for_upgrade(db)
    job_id = _start_upgrade_job(servers)

    # Wait, polling our own in-memory store. Total wait is bounded by
    # the slowest agent call, but each call has its own httpx timeout
    # so this can't run forever.
    deadline = time.time() + 600
    while time.time() < deadline:
        snap = _snapshot_upgrade_job(job_id)
        if snap and snap["done"]:
            break
        time.sleep(0.5)

    snap = _snapshot_upgrade_job(job_id) or {"nodes": [], "total": 0}
    results = [
        {
            "server_id": n["server_id"],
            "name": n["name"],
            "ok": bool(n.get("ok")),
            "scheduled": bool(n.get("scheduled")),
            "message": n.get("message", ""),
        }
        for n in snap["nodes"]
    ]
    audit_mod.record(
        db, user=user, action="admin.upgrade-all",
        resource_type="server", resource_id=None,
        details=(
            f"{len(results)} nodes; ok={sum(1 for r in results if r['ok'])}; "
            f"job_id={job_id}"
        ),
    )
    db.commit()
    return {
        "ok": all(r["ok"] for r in results) if results else True,
        "total": len(results),
        "results": results,
    }


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
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400,
            detail="Hysteria 2 does not use Reality x25519 keys",
        )
    if is_custom(s):
        raise HTTPException(
            status_code=400,
            detail="Reality keys belong to the custom config and are locked",
        )
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
    # We just pushed a fresh config and got an OK from the agent — its
    # liveness is confirmed for the next 10 s without another probe.
    _health_cache_set(
        s.id, online=True, xray_version="", xray_active=True,
    )
    return _server_to_dict(s, online=True)


@app.post("/api/servers/{server_id}/resync")
def api_server_resync(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    """Rebuild this server's xray config from the current DB state and
    push it to the agent. No keys, clients or server rows are touched —
    this is the escape hatch for picking up panel-side config changes
    (new routing rules, outbounds, etc.) after a panel upgrade without
    rotating Reality keys or having to add/remove a dummy client.
    """
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    try:
        _push_config(s, db)
    except AgentError as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    # Push succeeded — agent is alive. Refresh the cache so the next
    # /api/servers poll doesn't waste a probe on a known-good node.
    _health_cache_set(
        s.id, online=True, xray_version="", xray_active=True,
    )
    audit_mod.record(
        db, user=user, action="server.resync",
        resource_type="server", resource_id=s.id, details=s.name,
    )
    db.commit()
    return {"ok": True}


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


def _build_bridge_install_command(
    request: Request, token: str, domain: str = ""
) -> str:
    panel = _panel_base_url(request)
    installer = _install_repo_url()
    domain_arg = f' --domain "{domain}"' if domain else ""
    return (
        f'curl -fsSL {installer} | sudo bash -s -- '
        f'--bridge-enroll --panel-url "{panel}" --bridge-token "{token}"'
        f'{domain_arg} --yes'
    )


def _bridge_enrollment_to_dict(
    e: BridgeEnrollmentToken, request: Request
) -> dict:
    return {
        "id": e.id,
        "token": e.token,
        "server_id": e.server_id,
        "name": e.name,
        "public_host": e.public_host,
        "port": e.port,
        "agent_port": e.agent_port,
        "used_at": e.used_at,
        "created_at": e.created_at,
        "install_command": _build_bridge_install_command(
            request, e.token, e.public_host
        ),
    }


def _enrollment_to_dict(e: EnrollmentToken, request: Request) -> dict:
    payload = {
        "id": e.id,
        "token": e.token,
        "name": e.name,
        "display_name": getattr(e, "display_name", "") or "",
        "in_pool": bool(getattr(e, "in_pool", False)),
        "pool_tier": (getattr(e, "pool_tier", "") or ""),
        "mode": (getattr(e, "mode", "") or "standalone"),
        "protocol": normalise_protocol(getattr(e, "protocol", "")),
        "upstream_server_id": getattr(e, "upstream_server_id", None),
        "public_host": e.public_host,
        "port": e.port,
        "sni": e.sni,
        "dest": e.dest,
        "transport": (getattr(e, "transport", "") or "tcp"),
        "transport_path": (getattr(e, "transport_path", "") or ""),
        "agent_port": e.agent_port,
        "agent_token": e.agent_token,
        "used_at": e.used_at,
        "server_id": e.server_id,
        "created_at": e.created_at,
        "install_command": _build_install_command(request, e.token, e.public_host),
    }
    payload.update(_enrollment_protocol_settings(e))
    return payload


def _enrollment_protocol_settings(e: EnrollmentToken) -> dict:
    return {
        "hysteria_listen": getattr(e, "hysteria_listen", "") or "",
        "hysteria_auth_mode": getattr(e, "hysteria_auth_mode", "userpass") or "userpass",
        "hysteria_auth_password": getattr(e, "hysteria_auth_password", "") or "",
        "hysteria_tls_mode": getattr(e, "hysteria_tls_mode", "acme") or "acme",
        "hysteria_acme_email": getattr(e, "hysteria_acme_email", "") or "",
        "hysteria_cert_path": getattr(e, "hysteria_cert_path", "") or "",
        "hysteria_key_path": getattr(e, "hysteria_key_path", "") or "",
        "hysteria_obfs_type": getattr(e, "hysteria_obfs_type", "") or "",
        "hysteria_obfs_password": (
            getattr(e, "hysteria_obfs_password", "") or ""
        ),
        "hysteria_up_mbps": int(getattr(e, "hysteria_up_mbps", 0) or 0),
        "hysteria_down_mbps": int(getattr(e, "hysteria_down_mbps", 0) or 0),
        "hysteria_ignore_client_bandwidth": bool(
            getattr(e, "hysteria_ignore_client_bandwidth", False)
        ),
        "hysteria_congestion": (
            getattr(e, "hysteria_congestion", "bbr") or "bbr"
        ),
        "hysteria_bbr_profile": (
            getattr(e, "hysteria_bbr_profile", "standard") or "standard"
        ),
        "hysteria_disable_udp": bool(
            getattr(e, "hysteria_disable_udp", False)
        ),
        "hysteria_udp_idle_timeout": int(
            getattr(e, "hysteria_udp_idle_timeout", 60) or 60
        ),
        "hysteria_masquerade_url": (
            getattr(e, "hysteria_masquerade_url", "") or ""
        ),
        "hysteria_stats_port": int(
            getattr(e, "hysteria_stats_port", 9999) or 9999
        ),
        "hysteria_advanced_json": (
            getattr(e, "hysteria_advanced_json", "") or ""
        ),
        "sni_endpoint_enabled": bool(
            getattr(e, "sni_endpoint_enabled", False)
        ),
        "sni_endpoint_domain": (
            getattr(e, "sni_endpoint_domain", "") or ""
        ),
        "sni_endpoint_email": getattr(e, "sni_endpoint_email", "") or "",
        "sni_endpoint_port": int(
            getattr(e, "sni_endpoint_port", 9443) or 9443
        ),
    }


@app.get(
    "/api/servers/{server_id}/bridge/enrollments",
    response_model=list[BridgeEnrollmentOut],
)
def api_list_bridge_enrollments(
    server_id: int,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> list[dict]:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400,
            detail="Hysteria 2 cannot use a TCP HAProxy bridge",
        )
    rows = db.scalars(
        select(BridgeEnrollmentToken)
        .where(BridgeEnrollmentToken.server_id == server_id)
        .order_by(BridgeEnrollmentToken.id.desc())
    ).all()
    return [_bridge_enrollment_to_dict(row, request) for row in rows]


@app.post(
    "/api/servers/{server_id}/bridge/enrollments",
    response_model=BridgeEnrollmentOut,
    status_code=201,
)
def api_create_bridge_enrollment(
    server_id: int,
    body: BridgeEnrollmentCreateIn,
    request: Request,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400,
            detail=(
                "HAProxy bridges are TCP-only and cannot proxy Hysteria 2 "
                "QUIC/UDP nodes"
            ),
        )
    if body.port == body.agent_port:
        raise HTTPException(
            status_code=409,
            detail="bridge listener and bridge agent ports must differ",
        )
    if db.scalar(
        select(BridgeEnrollmentToken).where(
            BridgeEnrollmentToken.server_id == server_id,
            BridgeEnrollmentToken.used_at.is_(None),
        )
    ):
        raise HTTPException(
            status_code=409,
            detail="this node already has a pending bridge enrollment",
        )
    public_host = (body.public_host or "").strip()
    if public_host and (
        "://" in public_host or "/" in public_host or " " in public_host
    ):
        raise HTTPException(
            status_code=400,
            detail="bridge public_host must be a plain hostname or IP address",
        )
    row = BridgeEnrollmentToken(
        token=_secrets.token_urlsafe(24),
        server_id=s.id,
        name=body.name.strip(),
        public_host=public_host,
        port=body.port,
        agent_port=body.agent_port,
        agent_token=_secrets.token_hex(24),
    )
    db.add(row)
    audit_mod.record(
        db,
        user=user,
        action="server.bridge.enrollment_create",
        resource_type="server",
        resource_id=s.id,
        details=f"{row.name}; {public_host or 'auto'}:{row.port}",
    )
    db.commit()
    db.refresh(row)
    return _bridge_enrollment_to_dict(row, request)


@app.get(
    "/api/bridge-enroll/{token}",
    response_model=BridgeEnrollmentDetailsOut,
)
def api_bridge_enroll_details(
    token: str, db: Session = Depends(get_db)
) -> dict:
    row = db.scalar(
        select(BridgeEnrollmentToken).where(BridgeEnrollmentToken.token == token)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="unknown bridge token")
    if row.used_at is not None:
        raise HTTPException(status_code=400, detail="bridge token already used")
    s = db.get(Server, row.server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="target server not found")
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400, detail="Hysteria 2 cannot use a TCP HAProxy bridge"
        )
    return {
        "server_id": s.id,
        "name": row.name,
        "public_host": row.public_host,
        "port": row.port,
        "agent_port": row.agent_port,
        "agent_token": row.agent_token,
        "target_host": s.public_host,
        "target_port": s.port,
    }


@app.post("/api/bridge-enroll/{token}/complete")
def api_bridge_enroll_complete(
    token: str,
    body: BridgeCompleteIn,
    db: Session = Depends(get_db),
) -> dict:
    row = db.scalar(
        select(BridgeEnrollmentToken).where(BridgeEnrollmentToken.token == token)
    )
    if row is None:
        raise HTTPException(status_code=404, detail="unknown bridge token")
    if row.used_at is not None:
        raise HTTPException(status_code=400, detail="bridge token already used")
    s = db.get(Server, row.server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="target server not found")
    if is_hysteria2(s):
        raise HTTPException(
            status_code=400, detail="Hysteria 2 cannot use a TCP HAProxy bridge"
        )
    agent_url = body.agent_url.rstrip("/")
    public_host = (body.public_host or row.public_host or "").strip()
    if not public_host:
        raise HTTPException(
            status_code=400,
            detail="bridge public_host is required; pass --domain or set it in the panel",
        )
    bridge_agent = AgentClient(agent_url, row.agent_token)
    try:
        bridge_agent.health()
        result = bridge_agent.configure_haproxy_bridge(
            bridge_id=f"server-{s.id}",
            listen_port=row.port,
            target_host=s.public_host,
            target_port=s.port,
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(
            status_code=400, detail=f"bridge provisioning failed: {exc}"
        ) from exc
    s.bridge_enabled = True
    s.bridge_name = row.name
    s.bridge_public_host = public_host
    s.bridge_port = row.port
    s.bridge_agent_url = agent_url
    s.bridge_agent_token = row.agent_token
    row.public_host = public_host
    row.used_at = datetime.utcnow()
    db.commit()
    db.refresh(s)
    server_payload = _server_to_dict(s)
    client_rows = [
        _client_to_dict(c, s) for c in s.clients if not is_service_client(c)
    ]
    return {
        "ok": True,
        "server_id": s.id,
        "bridge_host": public_host,
        "bridge_port": row.port,
        "client_endpoint": server_payload["client_endpoint"],
        "server": server_payload,
        "links": [item["connection_link"] for item in client_rows],
        "target_host": s.public_host,
        "target_port": s.port,
        "haproxy": result,
    }


@app.delete("/api/servers/{server_id}/bridge", response_model=ServerOut)
def api_disable_bridge(
    server_id: int,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    s = db.get(Server, server_id)
    if s is None:
        raise HTTPException(status_code=404, detail="server not found")
    old = (
        f"{getattr(s, 'bridge_public_host', '')}:"
        f"{getattr(s, 'bridge_port', 443)}"
    )
    s.bridge_enabled = False
    audit_mod.record(
        db,
        user=user,
        action="server.bridge.disable",
        resource_type="server",
        resource_id=s.id,
        details=old,
    )
    db.commit()
    db.refresh(s)
    return _server_to_dict(s)


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
    try:
        protocol = normalise_protocol(body.protocol)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
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
    if (
        protocol == PROTOCOL_HYSTERIA2
        and (mode != "standalone" or body.upstream_server_id)
    ):
        raise HTTPException(
            status_code=400,
            detail="Hysteria 2 nodes support standalone mode only",
        )
    if protocol == PROTOCOL_HYSTERIA2:
        if body.sni_endpoint_enabled:
            raise HTTPException(
                status_code=400,
                detail=(
                    "a separate Reality SNI endpoint cannot be enabled on "
                    "a Hysteria 2 node"
                ),
            )
        try:
            hysteria_auth_mode, hysteria_auth_password = _prepare_hysteria_auth(
                body.hysteria_auth_mode, body.hysteria_auth_password
            )
            hysteria_obfs_type, hysteria_obfs_password = _prepare_hysteria_obfs(
                body.hysteria_obfs_type, body.hysteria_obfs_password
            )
            build_hysteria_config(
                port=body.port,
                listen=body.hysteria_listen,
                sni=_validate_sni(body.sni),
                tls_mode=body.hysteria_tls_mode,
                acme_email=body.hysteria_acme_email,
                cert_path=body.hysteria_cert_path,
                key_path=body.hysteria_key_path,
                clients=[],
                auth_mode=hysteria_auth_mode,
                auth_password=hysteria_auth_password,
                stats_secret="enrollment-validation",
                stats_port=body.hysteria_stats_port,
                obfs_type=hysteria_obfs_type,
                obfs_password=hysteria_obfs_password,
                up_mbps=body.hysteria_up_mbps,
                down_mbps=body.hysteria_down_mbps,
                ignore_client_bandwidth=body.hysteria_ignore_client_bandwidth,
                congestion=body.hysteria_congestion,
                bbr_profile=body.hysteria_bbr_profile,
                disable_udp=body.hysteria_disable_udp,
                udp_idle_timeout_seconds=body.hysteria_udp_idle_timeout,
                masquerade_url=body.hysteria_masquerade_url,
                advanced_json=body.hysteria_advanced_json,
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        hysteria_auth_mode = (body.hysteria_auth_mode or "userpass").strip().lower()
        hysteria_auth_password = (body.hysteria_auth_password or "").strip()
        hysteria_obfs_type = (body.hysteria_obfs_type or "").strip().lower()
        hysteria_obfs_password = (body.hysteria_obfs_password or "").strip()
    if protocol != PROTOCOL_HYSTERIA2 and body.sni_endpoint_enabled:
        endpoint_domain = _validate_sni(body.sni_endpoint_domain)
        if not (body.sni_endpoint_email or "").strip():
            raise HTTPException(
                status_code=400, detail="SNI endpoint ACME email is required"
            )
        if body.sni_endpoint_port in (body.port, body.agent_port):
            raise HTTPException(
                status_code=409,
                detail=(
                    "SNI endpoint port must differ from the VPN and agent ports"
                ),
            )
        body.sni_endpoint_domain = endpoint_domain
    # whitelist-front nodes need a foreign exit picked up-front so the
    # very first config push wires the chain correctly. The upstream
    # MUST be a standalone node — chaining a chain would loop.
    upstream_id = body.upstream_server_id or None
    # Auto-promote a standalone enrollment to whitelist-front when the
    # admin attaches an upstream. The dashboard's «🛡 Fallback-нода»
    # button reuses the standalone+fallback path but can optionally
    # ship an upstream — when set, we want the resulting node to chain
    # into a foreign exit (so the fallback shield actually bypasses
    # whitelists), not just to be a parallel standalone in the
    # fallback bucket. Balancer mode never accepts an upstream.
    if mode == "standalone" and upstream_id:
        mode = WHITELIST_FRONT_MODE
    if mode == "balancer":
        upstream_id = None
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
    # Resolve the auto-balance tier for the enrollment. The same
    # in_pool↔primary mapping the API enforces on the Server row
    # applies here so the value carried into ``api_enroll_complete``
    # is already canonical.
    try:
        tier = auto_balance.normalise_tier(body.pool_tier)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if mode == "balancer":
        # Balancers are routers — they never live inside a pool tier.
        tier = auto_balance.TIER_NONE
    elif tier == auto_balance.TIER_PRIMARY:
        # Whitelist-front nodes can't be primary (they live behind RU
        # IPs by definition); silently coerce to fallback so the UI's
        # «🛡 Нода обхода» path still works even when the operator
        # forgets to flip the dropdown.
        if mode == WHITELIST_FRONT_MODE:
            tier = auto_balance.TIER_FALLBACK
        in_pool = True
    elif tier == auto_balance.TIER_FALLBACK:
        # Fallback nodes are not in the legacy balancer pool.
        in_pool = False
    elif in_pool:
        # Legacy: in_pool=True without explicit tier → primary.
        tier = auto_balance.TIER_PRIMARY
    try:
        enroll_transport = normalise_transport(body.transport)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    enroll_transport_path = (body.transport_path or "").strip()
    enrollment = EnrollmentToken(
        token=_secrets.token_urlsafe(24),
        name=body.name,
        display_name=(body.display_name or "").strip(),
        in_pool=in_pool,
        pool_tier=tier,
        mode=mode,
        protocol=protocol,
        upstream_server_id=upstream_id,
        public_host=body.public_host or "",
        port=body.port,
        sni=body.sni,
        dest=body.dest,
        transport=enroll_transport,
        transport_path=enroll_transport_path,
        hysteria_listen=body.hysteria_listen,
        hysteria_auth_mode=hysteria_auth_mode,
        hysteria_auth_password=hysteria_auth_password,
        hysteria_tls_mode=body.hysteria_tls_mode,
        hysteria_acme_email=body.hysteria_acme_email,
        hysteria_cert_path=body.hysteria_cert_path,
        hysteria_key_path=body.hysteria_key_path,
        hysteria_obfs_type=hysteria_obfs_type,
        hysteria_obfs_password=hysteria_obfs_password,
        hysteria_up_mbps=body.hysteria_up_mbps,
        hysteria_down_mbps=body.hysteria_down_mbps,
        hysteria_ignore_client_bandwidth=body.hysteria_ignore_client_bandwidth,
        hysteria_congestion=body.hysteria_congestion,
        hysteria_bbr_profile=body.hysteria_bbr_profile,
        hysteria_disable_udp=body.hysteria_disable_udp,
        hysteria_udp_idle_timeout=body.hysteria_udp_idle_timeout,
        hysteria_masquerade_url=body.hysteria_masquerade_url,
        hysteria_stats_secret=_secrets.token_urlsafe(32),
        hysteria_stats_port=body.hysteria_stats_port,
        hysteria_advanced_json=body.hysteria_advanced_json,
        sni_endpoint_enabled=bool(body.sni_endpoint_enabled),
        sni_endpoint_domain=body.sni_endpoint_domain,
        sni_endpoint_email=body.sni_endpoint_email,
        sni_endpoint_port=body.sni_endpoint_port,
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
    payload = {
        "name": e.name,
        "port": e.port,
        "sni": e.sni,
        "dest": e.dest,
        "agent_port": e.agent_port,
        "agent_token": e.agent_token,
        "public_host": e.public_host,
        "protocol": normalise_protocol(getattr(e, "protocol", "")),
        "transport": (getattr(e, "transport", "") or "tcp"),
        "transport_path": (getattr(e, "transport_path", "") or ""),
    }
    payload.update(_enrollment_protocol_settings(e))
    return payload


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
    protocol = normalise_protocol(getattr(e, "protocol", ""))
    kp = {"private_key": "", "public_key": ""}
    if protocol == PROTOCOL_VLESS:
        try:
            kp = agent.gen_keypair()
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=400, detail=f"keypair generation failed: {exc}"
            ) from exc

    # Installer may override sni/dest/port if it auto-probed a better SNI on
    # the node than what the admin pre-filled on the enrollment. This is the
    # common case (default panel SNI is rutube.ru which is often unreachable
    # from EU DCs).
    if protocol == PROTOCOL_HYSTERIA2:
        # Hysteria's TLS domain and UDP listen expression are explicit
        # enrollment settings; Xray's automatic Reality SNI probe must not
        # override either of them.
        eff_sni = e.sni.strip()
        eff_dest = e.dest.strip()
        eff_port = e.port
    else:
        eff_sni = (body.sni or e.sni).strip()
        eff_dest = (body.dest or e.dest).strip()
        eff_port = int(body.port) if body.port else e.port

    if bool(getattr(e, "sni_endpoint_enabled", False)):
        endpoint_port = int(getattr(e, "sni_endpoint_port", 9443) or 9443)
        if endpoint_port in (eff_port, int(getattr(e, "agent_port", 8765) or 8765)):
            raise HTTPException(
                status_code=409,
                detail=(
                    "SNI endpoint port must differ from the VPN and agent ports"
                ),
            )
        try:
            endpoint = agent.provision_sni_endpoint(
                domain=getattr(e, "sni_endpoint_domain", "") or "",
                email=getattr(e, "sni_endpoint_email", "") or "",
                port=endpoint_port,
                vpn_port=eff_port,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=400,
                detail=f"SNI endpoint provisioning failed: {exc}",
            ) from exc
        eff_sni = str(endpoint.get("domain") or e.sni).strip()
        eff_dest = str(endpoint.get("dest") or f"127.0.0.1:{endpoint_port}")
    enrolled_mode = (getattr(e, "mode", "") or "standalone") or "standalone"
    enrolled_in_pool = (
        bool(getattr(e, "in_pool", False))
        and enrolled_mode not in ("balancer", WHITELIST_FRONT_MODE)
    )
    # Carry the enrollment's tier through to the new Server row.
    # Balancers can't sit in a tier; whitelist-fronts always land in
    # ``fallback`` (they exist to take over when primary nodes go
    # dark). A standalone with ``in_pool=True`` defaults to primary
    # for backwards compatibility with older enrollments that didn't
    # know about tiers.
    enrolled_pool_tier = (getattr(e, "pool_tier", "") or "")
    if enrolled_mode == "balancer":
        enrolled_pool_tier = auto_balance.TIER_NONE
    elif enrolled_mode == WHITELIST_FRONT_MODE:
        if enrolled_pool_tier != auto_balance.TIER_FALLBACK:
            enrolled_pool_tier = auto_balance.TIER_FALLBACK
    elif enrolled_in_pool and not enrolled_pool_tier:
        enrolled_pool_tier = auto_balance.TIER_PRIMARY
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
        pool_tier=enrolled_pool_tier,
        mode=enrolled_mode,
        upstream_server_id=enrolled_upstream_id,
        protocol=protocol,
        agent_url=agent_url,
        agent_token=e.agent_token,
        public_host=public_host,
        port=eff_port,
        sni=eff_sni,
        dest=eff_dest,
        transport=(getattr(e, "transport", "") or "tcp"),
        transport_path=(getattr(e, "transport_path", "") or ""),
        private_key=kp["private_key"],
        public_key=kp["public_key"],
        short_id=_short_id() if protocol == PROTOCOL_VLESS else "",
        hysteria_listen=getattr(e, "hysteria_listen", "") or "",
        hysteria_auth_mode=getattr(e, "hysteria_auth_mode", "userpass") or "userpass",
        hysteria_auth_password=getattr(e, "hysteria_auth_password", "") or "",
        hysteria_tls_mode=getattr(e, "hysteria_tls_mode", "acme") or "acme",
        hysteria_acme_email=getattr(e, "hysteria_acme_email", "") or "",
        hysteria_cert_path=getattr(e, "hysteria_cert_path", "") or "",
        hysteria_key_path=getattr(e, "hysteria_key_path", "") or "",
        hysteria_obfs_type=getattr(e, "hysteria_obfs_type", "") or "",
        hysteria_obfs_password=(
            getattr(e, "hysteria_obfs_password", "") or ""
        ),
        hysteria_up_mbps=int(getattr(e, "hysteria_up_mbps", 0) or 0),
        hysteria_down_mbps=int(getattr(e, "hysteria_down_mbps", 0) or 0),
        hysteria_ignore_client_bandwidth=bool(
            getattr(e, "hysteria_ignore_client_bandwidth", False)
        ),
        hysteria_congestion=(
            getattr(e, "hysteria_congestion", "bbr") or "bbr"
        ),
        hysteria_bbr_profile=(
            getattr(e, "hysteria_bbr_profile", "standard") or "standard"
        ),
        hysteria_disable_udp=bool(
            getattr(e, "hysteria_disable_udp", False)
        ),
        hysteria_udp_idle_timeout=int(
            getattr(e, "hysteria_udp_idle_timeout", 60) or 60
        ),
        hysteria_masquerade_url=(
            getattr(e, "hysteria_masquerade_url", "") or ""
        ),
        hysteria_stats_secret=(
            getattr(e, "hysteria_stats_secret", "") or _secrets.token_urlsafe(32)
        ),
        hysteria_stats_port=int(
            getattr(e, "hysteria_stats_port", 9999) or 9999
        ),
        hysteria_advanced_json=(
            getattr(e, "hysteria_advanced_json", "") or ""
        ),
        sni_endpoint_enabled=bool(
            getattr(e, "sni_endpoint_enabled", False)
        ),
        sni_endpoint_domain=(
            getattr(e, "sni_endpoint_domain", "") or ""
        ),
        sni_endpoint_email=getattr(e, "sni_endpoint_email", "") or "",
        sni_endpoint_port=int(
            getattr(e, "sni_endpoint_port", 9443) or 9443
        ),
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
            uuid=(
                _secrets.token_urlsafe(24)
                if protocol == PROTOCOL_HYSTERIA2
                else str(uuidlib.uuid4())
            ),
            email=f"{server.name}-user1",
            label=server.name,
            flow=(
                "xtls-rprx-vision"
                if (
                    protocol == PROTOCOL_VLESS
                    and transport_supports_flow(server_transport(server))
                )
                else ""
            ),
        )
        db.add(first)
        db.commit()
        db.refresh(server)

    _provision_all_server_subscriptions_for_server(server, db)

    try:
        _push_config(server, db)
    except AgentError as exc:
        db.delete(server)
        db.commit()
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    # A fresh pool member means every existing balancer needs its
    # outbound list rebuilt so it starts probing this upstream.
    # Both tiers count: ``primary`` rows flip ``in_pool=True`` and
    # the legacy check below would catch them, but ``fallback`` rows
    # keep ``in_pool=False`` while still being valid balancer
    # upstreams (``pool_upstreams`` includes them too) — so resolve
    # the tier off the new Server row directly instead.
    if auto_balance.is_in_auto_balance(server):
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
    if bool(getattr(s, "provisioned", False)):
        rows = db.scalars(
            select(Client)
            .where(Client.subscription_id == s.id)
            .order_by(Client.id)
        ).all()
    elif s.include_all:
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
        "provisioned": bool(getattr(s, "provisioned", False)),
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


def _subscription_target_servers(
    *, include_all: bool, server_ids: Iterable[int], db: Session
) -> list[Server]:
    if include_all:
        rows = list(db.scalars(select(Server).order_by(Server.id)).all())
    else:
        wanted = {int(value) for value in server_ids}
        if not wanted:
            raise HTTPException(
                status_code=400,
                detail="select at least one server or enable include_all",
            )
        rows = list(
            db.scalars(
                select(Server).where(Server.id.in_(wanted)).order_by(Server.id)
            ).all()
        )
        found = {server.id for server in rows}
        missing = sorted(wanted - found)
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"unknown server ids: {missing}",
            )
    if not rows:
        raise HTTPException(status_code=400, detail="no servers are available")
    return rows


def _new_subscription_client(sub: Subscription, server: Server) -> Client:
    return Client(
        server_id=server.id,
        subscription_id=sub.id,
        uuid=(
            _secrets.token_urlsafe(24)
            if is_hysteria2(server)
            else str(uuidlib.uuid4())
        ),
        # The email is the same on every selected node, but uniqueness is
        # scoped to server_id. This makes xray stats easy to recognise while
        # every node still gets its own independent UUID/key.
        email=f"subscription-{sub.id}-{sub.token[:8]}",
        label=sub.name,
        flow=(
            "xtls-rprx-vision"
            if not is_hysteria2(server)
            and transport_supports_flow(server_transport(server))
            else ""
        ),
    )


def _owned_client_snapshot(client: Client) -> dict[str, Any]:
    return {
        "id": client.id,
        "server_id": client.server_id,
        "subscription_id": client.subscription_id,
        "uuid": client.uuid,
        "email": client.email,
        "label": client.label,
        "flow": client.flow,
        "sni": client.sni,
        "total_up": client.total_up,
        "total_down": client.total_down,
        "xray_up_baseline": client.xray_up_baseline,
        "xray_down_baseline": client.xray_down_baseline,
        "data_limit_bytes": client.data_limit_bytes,
        "expires_at": client.expires_at,
        "enabled": client.enabled,
    }


def _restore_owned_clients(
    sub: Subscription, snapshots: list[dict[str, Any]], db: Session
) -> None:
    current = list(
        db.scalars(select(Client).where(Client.subscription_id == sub.id)).all()
    )
    for client in current:
        db.delete(client)
    db.flush()
    for values in snapshots:
        db.add(Client(**values))
    db.commit()


def _sync_provisioned_subscription(
    sub: Subscription, target_servers: list[Server], db: Session
) -> list[Client]:
    """Reconcile one owned client per target server and push changed nodes.

    Database state is compensated and already-touched nodes are re-pushed if
    any agent rejects the change, preventing half-created subscriptions.
    """
    existing = list(
        db.scalars(
            select(Client)
            .where(Client.subscription_id == sub.id)
            .order_by(Client.id)
        ).all()
    )
    snapshots = [_owned_client_snapshot(client) for client in existing]
    by_server = {client.server_id: client for client in existing}
    target_by_id = {server.id: server for server in target_servers}
    affected_ids: set[int] = set()
    removed_emails: dict[int, list[str]] = {}

    for server_id, client in list(by_server.items()):
        if server_id not in target_by_id:
            affected_ids.add(server_id)
            removed_emails.setdefault(server_id, []).append(client.email)
            db.delete(client)
    for server_id, server in target_by_id.items():
        client = by_server.get(server_id)
        if client is None:
            db.add(_new_subscription_client(sub, server))
            affected_ids.add(server_id)
        elif client.label != sub.name:
            client.label = sub.name
    db.commit()

    pushed_ids: set[int] = set()
    try:
        for server_id in sorted(affected_ids):
            server = db.get(Server, server_id)
            if server is None:
                continue
            db.expire(server, ["clients"])
            _push_config(
                server,
                db,
                remove_emails=removed_emails.get(server_id, ()),
            )
            pushed_ids.add(server_id)
    except Exception as exc:  # noqa: BLE001
        _restore_owned_clients(sub, snapshots, db)
        # Best-effort external compensation. The original exception is kept
        # even if a node is currently too unhealthy to accept the rollback.
        for server_id in sorted(pushed_ids | {server_id}):
            server = db.get(Server, server_id)
            if server is None:
                continue
            try:
                db.expire(server, ["clients"])
                _push_config(server, db)
            except Exception:  # noqa: BLE001
                pass
        raise AgentError(f"could not provision subscription clients: {exc}") from exc

    return list(
        db.scalars(
            select(Client)
            .where(Client.subscription_id == sub.id)
            .order_by(Client.id)
        ).all()
    )


def _provision_all_server_subscriptions_for_server(
    server: Server, db: Session
) -> int:
    """Attach a newly-added node to every provisioned all-server feed.

    Callers are already about to push the server's initial config, so this
    helper only adds rows and lets that single push include all new clients.
    """
    count = 0
    subscriptions = db.scalars(
        select(Subscription).where(
            Subscription.provisioned.is_(True),
            Subscription.include_all.is_(True),
        )
    ).all()
    for sub in subscriptions:
        exists = db.scalar(
            select(Client.id).where(
                Client.subscription_id == sub.id,
                Client.server_id == server.id,
            )
        )
        if exists is None:
            db.add(_new_subscription_client(sub, server))
            count += 1
    if count:
        db.commit()
        db.expire(server, ["clients"])
    return count


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
        provisioned=not bool(body.client_ids),
        profile_title=(body.profile_title or "").strip(),
        support_url=(body.support_url or "").strip(),
        announce=(body.announce or "").strip(),
        provider_id=(body.provider_id or "").strip(),
        routing=(body.routing or "").strip(),
        update_interval_hours=int(body.update_interval_hours or 24),
    )
    if body.client_ids:
        # Backward-compatible legacy API: explicit existing client IDs still
        # create an aggregation and never take ownership of those rows.
        picked = list(
            db.scalars(select(Client).where(Client.id.in_(body.client_ids))).all()
        )
        sub.clients = picked
    db.add(sub)
    db.flush()
    if sub.provisioned:
        targets = _subscription_target_servers(
            include_all=sub.include_all,
            server_ids=body.server_ids,
            db=db,
        )
    else:
        targets = []
    db.commit()
    try:
        if sub.provisioned:
            _sync_provisioned_subscription(sub, targets, db)
    except AgentError as exc:
        db.delete(sub)
        db.commit()
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    db.refresh(sub)
    audit_mod.record(
        db,
        user=user,
        action="subscription.create",
        resource_type="subscription",
        resource_id=sub.id,
        details=(
            f"{sub.name}; provisioned={sub.provisioned}; "
            f"servers={','.join(str(s.id) for s in targets)}"
        ),
    )
    db.commit()
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
    original = {
        "name": sub.name,
        "include_all": sub.include_all,
        "provisioned": bool(getattr(sub, "provisioned", False)),
        "profile_title": sub.profile_title,
        "support_url": sub.support_url,
        "announce": sub.announce,
        "provider_id": sub.provider_id,
        "routing": sub.routing,
        "update_interval_hours": sub.update_interval_hours,
    }
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
    managed = bool(getattr(sub, "provisioned", False)) or body.server_ids is not None
    if managed:
        legacy_clients = list(sub.clients) if not original["provisioned"] else []
        sub.provisioned = True
        try:
            selected_ids = body.server_ids
            if selected_ids is None:
                selected_ids = [
                    client.server_id
                    for client in db.scalars(
                        select(Client).where(Client.subscription_id == sub.id)
                    ).all()
                ]
            targets = _subscription_target_servers(
                include_all=bool(sub.include_all),
                server_ids=selected_ids,
                db=db,
            )
            # Converting a legacy subscription does not delete or mutate the
            # old clients; it only stops aggregating them.
            if not original["provisioned"]:
                sub.clients = []
            _sync_provisioned_subscription(sub, targets, db)
        except (AgentError, HTTPException) as exc:
            for field, value in original.items():
                setattr(sub, field, value)
            if not original["provisioned"]:
                sub.clients = legacy_clients
            db.commit()
            if isinstance(exc, HTTPException):
                raise
            raise HTTPException(status_code=502, detail=str(exc)) from exc
    elif body.client_ids is not None:
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
    owned = list(
        db.scalars(select(Client).where(Client.subscription_id == sub.id)).all()
    )
    affected: dict[int, list[str]] = {}
    for client in owned:
        affected.setdefault(client.server_id, []).append(client.email)
    db.delete(sub)
    db.commit()
    warnings: list[str] = []
    for server_id, emails in affected.items():
        server = db.get(Server, server_id)
        if server is None:
            continue
        try:
            db.expire(server, ["clients"])
            _push_config(server, db, remove_emails=emails)
        except Exception as exc:  # noqa: BLE001
            warnings.append(f"{server.name}: {exc}")
    audit_mod.record(
        db,
        user=user,
        action="subscription.delete",
        resource_type="subscription",
        resource_id=sub_id,
        details=f"removed_clients={len(owned)}",
    )
    db.commit()
    return {"ok": True, "warnings": warnings}


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
    """Render the plaintext protocol URI list.

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
        _client_connection_link(
            c,
            server,
            label=_subscription_label(server, c, overrides=overrides),
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
    ab_settings: "Optional[dict]" = None,
) -> str:
    """Minimal sing-box subscription (outbounds only).

    Produces a valid config fragment that sing-box and Hiddify accept as a
    direct subscription — one vless outbound per active key, plus a selector
    referencing them. Clients can paste the URL into sing-box / Hiddify /
    NekoBox subscription boxes.

    When auto-balance tiers are configured (``pool_tier`` is non-empty
    on at least one server) we emit a hierarchical ``urltest`` block:

    ::

        Auto (urltest, probe_interval) ──► [⚡ Primary, 🛡 Fallback]
          ├─ ⚡ Primary  (urltest, probe_interval) ──► foreign nodes
          └─ 🛡 Fallback (urltest, probe_interval) ──► whitelist-front

    The top-level ``urltest`` is what sing-box / Hiddify dials. It
    probes each tier endpoint at ``probe_interval_seconds`` and picks
    the lowest-latency one. When primary nodes go dark for the user
    (e.g. РKN whitelist flips on and the foreign IPs stop responding),
    every primary outbound times out, the urltest auto-switches to
    the fallback group, and the user transparently lands on a
    whitelist-front node. Once the primary recovers, the next probe
    cycle switches back. Identical mechanics on Clash.
    """
    import json as _json

    settings = ab_settings or {
        "probe_url": auto_balance.DEFAULT_PROBE_URL,
        "probe_interval_seconds": auto_balance.DEFAULT_PROBE_INTERVAL_SECONDS,
        "tolerance_ms": auto_balance.DEFAULT_TOLERANCE_MS,
    }
    probe_url = settings["probe_url"]
    probe_interval = auto_balance.interval_string(settings["probe_interval_seconds"])
    tolerance_ms = int(settings["tolerance_ms"])

    outbounds: list[dict] = []
    tags: list[str] = []
    primary_tags: list[str] = []
    fallback_tags: list[str] = []
    for c, server in entries:
        tag = _subscription_label(server, c, overrides=overrides)
        tags.append(tag)
        tier = auto_balance.server_pool_tier(server)
        if tier == auto_balance.TIER_PRIMARY:
            primary_tags.append(tag)
        elif tier == auto_balance.TIER_FALLBACK:
            fallback_tags.append(tag)
        endpoint_host, endpoint_port = _server_client_endpoint(server)
        srv_transport = server_transport(server)
        eff_flow = effective_client_flow(c, server)
        if is_hysteria2(server):
            listen = normalise_hysteria_listen(
                getattr(server, "hysteria_listen", ""),
                fallback_port=server.port,
            )
            outbound = {
                "type": "hysteria2",
                "tag": tag,
                "server": endpoint_host,
                # Userpass is passed as ``username:password``; password mode
                # (autosetup-compatible) is passed as the shared secret.
                "password": _hysteria_client_auth(c, server),
                "tls": {
                    "enabled": True,
                    "server_name": server.sni,
                },
            }
            if "-" in listen:
                outbound["server_ports"] = [listen.replace("-", ":", 1)]
            else:
                outbound["server_port"] = int(listen)
            obfs_type = (getattr(server, "hysteria_obfs_type", "") or "").strip()
            if obfs_type:
                outbound["obfs"] = {
                    "type": obfs_type,
                    "password": (
                        getattr(server, "hysteria_obfs_password", "") or ""
                    ),
                }
            # Bandwidth is intentionally omitted. It is a per-device client
            # preference and the official Hysteria URI specification warns
            # subscription providers not to distribute it blindly.
        else:
            outbound = {
                "type": "vless",
                "tag": tag,
                "server": endpoint_host,
                "server_port": endpoint_port,
                "uuid": c.uuid,
                "flow": eff_flow,
                "packet_encoding": "xudp",
                "tls": {
                    "enabled": True,
                    "server_name": client_effective_sni(c, server),
                    "utls": {"enabled": True, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": True,
                        "public_key": server.public_key,
                        "short_id": server.short_id,
                    },
                },
            }
        # sing-box expresses non-default transports via a ``transport``
        # sub-block. xhttp shipped recently (sing-box >= 1.10) — older
        # clients will ignore the key and fall back to tcp, which won't
        # actually connect; admins who run pre-xhttp sing-box builds
        # should keep transport=tcp on those nodes.
        if not is_hysteria2(server) and srv_transport == "grpc":
            outbound["transport"] = {
                "type": "grpc",
                "service_name": server_transport_path(server),
            }
        elif not is_hysteria2(server) and srv_transport == "xhttp":
            outbound["transport"] = {
                "type": "xhttp",
                "path": server_transport_path(server),
                "host": client_effective_sni(c, server),
                "mode": "auto",
            }
        outbounds.append(outbound)
    # Selector + urltest groups in front so users can pick a node.
    # Order matters: the first entry in ``outbounds`` is what sing-box
    # exposes as the default / what Hiddify pins at the top of its UI.
    if tags:
        # Global "pick best of everything" urltest, used as the
        # eventual ground-truth default when no tier is configured.
        all_auto = {
            "type": "urltest",
            "tag": "auto",
            "outbounds": list(tags),
            "url": probe_url,
            "interval": probe_interval,
            "tolerance": tolerance_ms,
        }
        group_outbounds: list[dict] = [all_auto]
        selector_options: list[str] = ["auto"]
        default_choice: str = "auto"
        # When at least one tier is populated, build the hierarchical
        # auto-balance group. Top-level urltest = [primary_auto,
        # fallback_auto] (or whichever subset is populated). sing-box
        # picks the lowest-latency reachable tier. When primary tier
        # goes dark, the inner primary_auto times out, the top-level
        # urltest fails over to fallback_auto. Recovery happens on
        # the next probe cycle.
        tier_groups: list[dict] = []
        if primary_tags:
            primary_auto = {
                "type": "urltest",
                "tag": f"{auto_balance.PRIMARY_PREFIX}Auto",
                "outbounds": list(primary_tags),
                "url": probe_url,
                "interval": probe_interval,
                "tolerance": tolerance_ms,
            }
            tier_groups.append(primary_auto)
        if fallback_tags:
            fallback_auto = {
                "type": "urltest",
                "tag": f"{auto_balance.FALLBACK_PREFIX}Auto",
                "outbounds": list(fallback_tags),
                "url": probe_url,
                "interval": probe_interval,
                "tolerance": tolerance_ms,
            }
            tier_groups.append(fallback_auto)
        if tier_groups:
            balance_auto = {
                "type": "urltest",
                "tag": f"{auto_balance.PRIMARY_PREFIX}Auto-Balance",
                "outbounds": [g["tag"] for g in tier_groups],
                "url": probe_url,
                "interval": probe_interval,
                "tolerance": tolerance_ms,
            }
            # Order: top-level balancer first (this is what becomes
            # the default), then its children, then the global "auto".
            group_outbounds = [balance_auto, *tier_groups, all_auto]
            default_choice = balance_auto["tag"]
            selector_options = [
                balance_auto["tag"],
                *(g["tag"] for g in tier_groups),
                "auto",
            ]

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
    ab_settings: "Optional[dict]" = None,
) -> str:
    """Clash.Meta / Mihomo subscription (proxies + proxy-group).

    Emits a YAML fragment with vless+reality proxies plus the same
    hierarchical url-test groups as ``_render_singbox``: one
    ``url-test`` per tier and a wrapping ``fallback`` group on top.
    Clash.Meta's ``fallback`` group probes its members at the
    configured interval and dials the first reachable one — so when
    primary nodes go dark, traffic transparently falls through to
    fallback nodes; recovery is symmetric. Mihomo and recent
    Clash.Meta builds support vless+reality fully.
    """
    import yaml  # type: ignore

    settings = ab_settings or {
        "probe_url": auto_balance.DEFAULT_PROBE_URL,
        "probe_interval_seconds": auto_balance.DEFAULT_PROBE_INTERVAL_SECONDS,
        "tolerance_ms": auto_balance.DEFAULT_TOLERANCE_MS,
    }
    probe_url = settings["probe_url"]
    interval_seconds = max(1, int(settings["probe_interval_seconds"]))
    tolerance_ms = int(settings["tolerance_ms"])

    proxies: list[dict] = []
    names: list[str] = []
    primary_names: list[str] = []
    fallback_names: list[str] = []
    for c, server in entries:
        name = _subscription_label(server, c, overrides=overrides)
        names.append(name)
        tier = auto_balance.server_pool_tier(server)
        if tier == auto_balance.TIER_PRIMARY:
            primary_names.append(name)
        elif tier == auto_balance.TIER_FALLBACK:
            fallback_names.append(name)
        endpoint_host, endpoint_port = _server_client_endpoint(server)
        srv_transport = server_transport(server)
        eff_flow = effective_client_flow(c, server)
        if is_hysteria2(server):
            listen = normalise_hysteria_listen(
                getattr(server, "hysteria_listen", ""),
                fallback_port=server.port,
            )
            proxy = {
                "name": name,
                "type": "hysteria2",
                "server": endpoint_host,
                "port": int(listen.split("-", 1)[0]),
                "password": _hysteria_client_auth(c, server),
                "sni": server.sni,
                "skip-cert-verify": False,
            }
            if "-" in listen:
                proxy["ports"] = listen
            obfs_type = (getattr(server, "hysteria_obfs_type", "") or "").strip()
            if obfs_type:
                proxy["obfs"] = obfs_type
                proxy["obfs-password"] = (
                    getattr(server, "hysteria_obfs_password", "") or ""
                )
        else:
            proxy = {
                "name": name,
                "type": "vless",
                "server": endpoint_host,
                "port": endpoint_port,
                "uuid": c.uuid,
                "network": srv_transport if srv_transport in ("grpc",) else "tcp",
                "tls": True,
                "udp": True,
                "flow": eff_flow,
                "servername": client_effective_sni(c, server),
                "client-fingerprint": "chrome",
                "reality-opts": {
                    "public-key": server.public_key,
                    "short-id": server.short_id,
                },
            }
        if not is_hysteria2(server) and srv_transport == "grpc":
            proxy["grpc-opts"] = {
                "grpc-service-name": server_transport_path(server),
            }
        elif not is_hysteria2(server) and srv_transport == "xhttp":
            # Clash.Meta doesn't have first-class xhttp; the closest
            # equivalent is the ``ws``-like ``h2`` shim. We expose the
            # raw config so admins who run a Clash.Meta build with the
            # xhttp PR merged still get a working entry; others fall
            # back to tcp+reality and need to use sing-box / Hiddify
            # instead.
            proxy["network"] = "xhttp"
            proxy["xhttp-opts"] = {
                "path": server_transport_path(server),
                "host": client_effective_sni(c, server),
                "mode": "auto",
            }
        proxies.append(proxy)
    # Build proxy-groups. One "auto" url-test over everything (always
    # present when there are proxies), plus tier-specific groups when
    # any server has a tier assigned. The wrapping balance group is a
    # ``fallback`` so Clash.Meta sticks with the first reachable child
    # tier and only flips when its members all go dark — matching the
    # primary-preferred semantics of the sing-box urltest hierarchy.
    groups: list[dict] = []
    top_options: list[str] = []
    if names:
        primary_tag = f"{auto_balance.PRIMARY_PREFIX}Auto"
        fallback_tag = f"{auto_balance.FALLBACK_PREFIX}Auto"
        balance_tag = f"{auto_balance.PRIMARY_PREFIX}Auto-Balance"
        tier_tags: list[str] = []
        if primary_names:
            groups.append(
                {
                    "name": primary_tag,
                    "type": "url-test",
                    "proxies": list(primary_names),
                    "url": probe_url,
                    "interval": interval_seconds,
                    "tolerance": tolerance_ms,
                }
            )
            tier_tags.append(primary_tag)
        if fallback_names:
            groups.append(
                {
                    "name": fallback_tag,
                    "type": "url-test",
                    "proxies": list(fallback_names),
                    "url": probe_url,
                    "interval": interval_seconds,
                    "tolerance": tolerance_ms,
                }
            )
            tier_tags.append(fallback_tag)
        if tier_tags:
            groups.append(
                {
                    "name": balance_tag,
                    # ``fallback`` (not url-test) so Clash sticks with the
                    # first healthy child tier instead of constantly
                    # racing them — this is what gives us the
                    # "primary preferred, fallback only on outage"
                    # behaviour.
                    "type": "fallback",
                    "proxies": tier_tags,
                    "url": probe_url,
                    "interval": interval_seconds,
                }
            )
            top_options.append(balance_tag)
            top_options.extend(tier_tags)
        groups.append(
            {
                "name": "auto",
                "type": "url-test",
                "proxies": list(names),
                "url": probe_url,
                "interval": interval_seconds,
                "tolerance": tolerance_ms,
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
        ab_settings=auto_balance.get_settings(db),
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
    ab_settings: "Optional[dict]" = None,
) -> Response:
    if fmt in ("singbox", "sing-box", "json"):
        body = _render_singbox(
            entries, sub_name, overrides=overrides, ab_settings=ab_settings,
        )
        return Response(
            content=body,
            media_type="application/json; charset=utf-8",
            headers=headers,
        )
    if fmt == "clash":
        body = _render_clash(
            entries, sub_name, overrides=overrides, ab_settings=ab_settings,
        )
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

    # Default: base64(protocol URI list) — legacy v2ray subscription envelope.
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


# ---------- encrypted GitHub backups ----------
@app.get("/api/backups/settings", response_model=BackupSettingsOut)
def api_get_backup_settings(
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    return backups.get_settings(db).public_dict()


@app.patch("/api/backups/settings", response_model=BackupSettingsOut)
def api_update_backup_settings(
    body: BackupSettingsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    patch = body.model_dump(exclude_unset=True)
    try:
        settings = backups.update_settings(db, **patch)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="backup.settings.update",
        resource_type="backup",
        resource_id="github",
        details=",".join(
            sorted(
                key for key in patch
                if key not in {"github_token", "encryption_password"}
            )
        ),
    )
    db.commit()
    return settings.public_dict()


@app.post("/api/backups/run", response_model=BackupRunOut)
def api_run_backup_now(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = backups.run_backup(trigger=f"manual:{user.username}")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        status = 409 if "already running" in str(exc) else 502
        raise HTTPException(status_code=status, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="backup.manual",
        resource_type="backup",
        resource_id=result.get("github_path", ""),
        details=f"bytes={result.get('size_bytes', 0)}",
    )
    db.commit()
    return result


@app.post("/api/backups/export")
def api_export_backup(
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> Response:
    try:
        payload, filename, created_at = backups.export_backup()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="backup.export",
        resource_type="backup",
        resource_id=filename,
        details=f"created_at={created_at}; bytes={len(payload)}",
    )
    db.commit()
    return Response(
        content=payload,
        media_type="application/vnd.xnpanel.backup",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.post("/api/backups/import/inspect", response_model=BackupImportPreviewOut)
async def api_inspect_backup_import(
    backup_file: UploadFile = File(...),
    encryption_password: str = Form(...),
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    payload = await backup_file.read(backups.MAX_IMPORT_BYTES + 1)
    if len(payload) > backups.MAX_IMPORT_BYTES:
        raise HTTPException(status_code=413, detail="backup file is too large")
    try:
        preview = backups.stage_import(payload, encryption_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="backup.import.inspect",
        resource_type="backup",
        resource_id=preview["restore_id"],
        details=(
            f"created_at={preview.get('created_at', '')}; "
            f"database_bytes={preview.get('database_bytes', 0)}"
        ),
    )
    db.commit()
    return preview


@app.post(
    "/api/backups/import/{restore_id}/apply",
    response_model=BackupImportApplyOut,
)
def api_apply_backup_import(
    restore_id: str,
    body: BackupImportApplyIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    try:
        result = backups.schedule_import(
            restore_id, confirmation=body.confirmation
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="backup.import.apply",
        resource_type="backup",
        resource_id=restore_id,
        details="restore scheduled; panel will restart",
        notify=True,
    )
    db.commit()
    return result


# ---------- auto-balance settings ----------
# Panel-wide knobs that steer the hierarchical urltest emitted into
# every sing-box / Clash subscription. Probing is entirely client-side
# (sing-box / Hiddify / Karing / Clash all run their own probes), so
# changes here only affect newly-fetched subscriptions — existing
# clients won't repick a new probe URL until they re-fetch.
@app.get("/api/load-balancer/settings", response_model=LoadBalancerSettingsOut)
def api_get_load_balancer_settings(
    _: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    return auto_balance.get_settings(db)


@app.patch("/api/load-balancer/settings", response_model=LoadBalancerSettingsOut)
def api_update_load_balancer_settings(
    body: LoadBalancerSettingsIn,
    user: User = Depends(current_user),
    db: Session = Depends(get_db),
) -> dict:
    patch = body.model_dump(exclude_unset=True)
    try:
        result = auto_balance.update_settings(
            db,
            probe_url=patch.get("probe_url"),
            probe_interval_seconds=patch.get("probe_interval_seconds"),
            tolerance_ms=patch.get("tolerance_ms"),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    audit_mod.record(
        db,
        user=user,
        action="auto_balance.settings.update",
        resource_type="auto_balance",
        resource_id="settings",
        details=",".join(sorted(patch.keys())),
    )
    db.commit()
    return result


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

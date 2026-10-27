"""Shared helpers for pushing xray configs to agents.

Factored out of ``panel.app`` so ``panel.tg_bots`` can use the same
mode-aware logic (standalone vs balancer) without a circular import.
"""
from __future__ import annotations

import json
import functools
import logging
import os
import threading
import uuid as uuidlib
from datetime import datetime, timedelta
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .agent_client import AgentClient, AgentError
from .auto_balance import TIER_FALLBACK, TIER_PRIMARY, server_pool_tier
from .models import (
    Bridge,
    BridgeServerBinding,
    Client,
    Server,
    Setting,
    effective_client_flow,
    server_all_snis,
    server_ip_region,
    server_transport,
    server_transport_path,
    server_warp_domains,
    transport_supports_flow,
)
from .hysteria_config import build_hysteria_config, is_hysteria2, is_vless_ws_tls
from .xray_config import (
    SERVICE_BALANCERS,
    _ip_region_routing_caps,
    apply_warp_config,
    apply_torrent_policy,
    build_balancer_config,
    build_config,
    build_vless_ws_tls_config,
    build_whitelist_front_config,
)

log = logging.getLogger(__name__)


def _apply_server_torrent_policy(config: dict, server: Server, db: Session | None) -> None:
    allowed_tags: set[str] = set()
    if db is not None:
        siblings = db.scalars(select(Server).where(Server.agent_url == server.agent_url)).all()
    else:
        siblings = [server]
    for sibling in siblings:
        if not bool(getattr(sibling, "torrent_allowed", False)):
            continue
        if sibling.mode == "custom" and sibling.custom_inbound_tag:
            allowed_tags.add(sibling.custom_inbound_tag)
        else:
            allowed_tags.add("WS" if is_vless_ws_tls(sibling) else "vless-reality")
    panel_public_url = os.getenv("PANEL_PUBLIC_URL", "").rstrip("/")
    apply_torrent_policy(
        config,
        allowed_tags,
        webhook_url=f"{panel_public_url}/api/torrent/hit" if panel_public_url else "",
        webhook_token=server.agent_token,
    )

_agent_config_locks: dict[str, threading.RLock] = {}
_agent_config_locks_guard = threading.Lock()


def agent_config_lock(agent_url: str):
    """Share one read/modify/write lock across panel records on one host."""
    key = agent_url.rstrip("/")
    with _agent_config_locks_guard:
        return _agent_config_locks.setdefault(key, threading.RLock())


def _serialized_custom_config(func):
    @functools.wraps(func)
    def wrapped(server, *args, **kwargs):
        with agent_config_lock(server.agent_url):
            return func(server, *args, **kwargs)
    return wrapped

SERVICE_ROUTING_SETTING_KEY = "service_routing.enabled"
SERVICE_ROUTING_EXCLUDED_NODES_SETTING_KEY = "service_routing.excluded_exit_node_ids"
SERVICE_ROUTING_SERVICES = frozenset(("youtube", "gemini", "tiktok", "games"))
SERVICE_ROUTING_MAX_CHECK_AGE_S = max(
    3600, int(os.environ.get("SERVICE_ROUTING_MAX_CHECK_AGE_S", "86400") or 86400)
)
PROXY_PROTOCOL_PORT_BASE = 56000
PROXY_PROTOCOL_PORT_MAX = 64999


def bridge_proxy_protocol_port(server: Server | int) -> int:
    """Return the stable, bridge-only PROXY protocol listener port."""

    server_id = int(server if isinstance(server, int) else server.id)
    port = PROXY_PROTOCOL_PORT_BASE + server_id
    if port > PROXY_PROTOCOL_PORT_MAX:
        raise ValueError("server id is too large for the managed PROXY port range")
    if not isinstance(server, int) and port == int(server.port):
        raise ValueError("managed PROXY port collides with the public VPN port")
    return port


def bridge_proxy_sources(db: Session, server: Server) -> list[str]:
    """Return every enabled bridge endpoint/source trusted by this node."""

    rows = db.scalars(
        select(BridgeServerBinding)
        .join(Bridge, Bridge.id == BridgeServerBinding.bridge_id)
        .where(
            BridgeServerBinding.server_id == server.id,
            BridgeServerBinding.enabled.is_(True),
            Bridge.enabled.is_(True),
        )
        .order_by(BridgeServerBinding.id)
    ).all()
    values: list[str] = []
    for row in rows:
        for value in (row.bridge.agent_url, row.bridge.public_host):
            cleaned = str(value or "").strip()
            if cleaned and cleaned not in values:
                values.append(cleaned)
    return values


def _prepare_bridge_proxy_ingress(
    agent: AgentClient, db: Session | None, server: Server
) -> int | None:
    """Apply PROXY ingress only when this server has an enabled bridge.

    A regular node does not need this firewall service at all.  Calling the
    management endpoint with ``enabled=False`` during every ordinary config
    push was both needless and made first enrollment depend on systemd/iptables
    on a completely unrelated path.
    """

    if db is None:
        return None
    sources = bridge_proxy_sources(db, server)
    if not sources:
        return None
    port = bridge_proxy_protocol_port(server)
    agent.configure_proxy_protocol_ingress(
        port=port,
        trusted_sources=sources,
        enabled=True,
    )
    return port


def service_routing_enabled(db: Session) -> set[str]:
    """Return globally enabled capability routes, defaulting to all."""

    row = db.get(Setting, SERVICE_ROUTING_SETTING_KEY)
    if row is None or not row.value:
        return set(SERVICE_ROUTING_SERVICES)
    try:
        values = json.loads(row.value)
    except (TypeError, ValueError):
        log.warning("invalid %s setting; using safe defaults", SERVICE_ROUTING_SETTING_KEY)
        return set(SERVICE_ROUTING_SERVICES)
    if not isinstance(values, dict):
        return set(SERVICE_ROUTING_SERVICES)
    return {
        service
        for service in SERVICE_ROUTING_SERVICES
        if bool(values.get(service, True))
    }


def set_service_routing_enabled(db: Session, service: str, enabled: bool) -> set[str]:
    if service not in SERVICE_ROUTING_SERVICES:
        raise ValueError("unknown service route")
    current = service_routing_enabled(db)
    if enabled:
        current.add(service)
    else:
        current.discard(service)
    value = json.dumps(
        {name: name in current for name in sorted(SERVICE_ROUTING_SERVICES)},
        separators=(",", ":"),
    )
    row = db.get(Setting, SERVICE_ROUTING_SETTING_KEY)
    if row is None:
        db.add(Setting(key=SERVICE_ROUTING_SETTING_KEY, value=value))
    else:
        row.value = value
    return current


def service_routing_excluded_exit_node_ids(db: Session) -> set[int]:
    row = db.get(Setting, SERVICE_ROUTING_EXCLUDED_NODES_SETTING_KEY)
    if row is None or not row.value:
        return set()
    try:
        values = json.loads(row.value)
    except (TypeError, ValueError):
        log.warning(
            "invalid %s setting; using an empty exclusion set",
            SERVICE_ROUTING_EXCLUDED_NODES_SETTING_KEY,
        )
        return set()
    if not isinstance(values, list):
        return set()
    result: set[int] = set()
    for value in values:
        try:
            node_id = int(value)
        except (TypeError, ValueError):
            continue
        if node_id > 0:
            result.add(node_id)
    return result


def set_service_routing_node_enabled(
    db: Session, server_id: int, enabled: bool
) -> set[int]:
    """Include or exclude a node as a service-specific egress target."""
    if db.get(Server, int(server_id)) is None:
        raise ValueError("server not found")
    excluded = service_routing_excluded_exit_node_ids(db)
    if enabled:
        excluded.discard(int(server_id))
    else:
        excluded.add(int(server_id))
    value = json.dumps(sorted(excluded), separators=(",", ":"))
    row = db.get(Setting, SERVICE_ROUTING_EXCLUDED_NODES_SETTING_KEY)
    if row is None:
        db.add(Setting(key=SERVICE_ROUTING_EXCLUDED_NODES_SETTING_KEY, value=value))
    else:
        row.value = value
    return excluded


def service_routing_snapshot(db: Session) -> dict:
    """Describe calculated routes; valid live egress preferences may differ."""

    enabled = service_routing_enabled(db)
    excluded = service_routing_excluded_exit_node_ids(db)
    nodes = [
        server
        for server in db.scalars(
            select(Server)
            .where(Server.mode == "standalone")
            .order_by(Server.id)
        ).all()
        if not is_hysteria2(server) and not is_vless_ws_tls(server)
    ]
    capabilities = {
        server.id: _ip_region_routing_caps(server_ip_region(server))
        for server in nodes
    }
    node_rows = [
        {
            "id": server.id,
            "name": server.name,
            "display_name": server.display_name or server.name,
            "public_host": server.public_host,
            "capabilities": sorted(capabilities[server.id]),
            "checked_at": server.ip_region_checked_at,
            "error": server.ip_region_error or "",
            "exit_enabled": server.id not in excluded and _service_exit_ready(server),
        }
        for server in nodes
    ]
    routes: list[dict] = []
    for source in nodes:
        for service in sorted(SERVICE_ROUTING_SERVICES):
            targets = [
                target.id
                for target in nodes
                if (
                    target.id != source.id
                    and target.id not in excluded
                    and _service_exit_ready(target)
                    and service in capabilities[target.id]
                )
            ]
            targets.sort()
            if service not in enabled:
                mode = "disabled"
                targets = []
            elif service in capabilities[source.id]:
                mode = "direct"
                targets = []
            elif targets:
                mode = "forward"
                targets = [targets[source.id % len(targets)]]
            else:
                mode = "unavailable"
            routes.append(
                {
                    "source_id": source.id,
                    "service": service,
                    "mode": mode,
                    "target_ids": targets,
                }
            )
    return {
        "selection_basis": "calculated",
        "enabled": {
            service: service in enabled
            for service in sorted(SERVICE_ROUTING_SERVICES)
        },
        "nodes": node_rows,
        "routes": routes,
    }


def _service_exit_ready(server: Server) -> bool:
    """Admit only recently verified and reachable service egress nodes."""
    checked_at = getattr(server, "ip_region_checked_at", None)
    return bool(
        not is_hysteria2(server)
        and not is_vless_ws_tls(server)
        and not bool(getattr(server, "tspu_blocked", False))
        and checked_at
        and checked_at >= datetime.utcnow() - timedelta(seconds=SERVICE_ROUTING_MAX_CHECK_AGE_S)
        and not str(getattr(server, "ip_region_error", "") or "").strip()
    )


# Label applied to all Client rows that the panel auto-creates on pool
# upstreams so a balancer node can authenticate its outbounds. Admin UI
# and the TG bot filter rows with this label out of every listing so
# they look invisible to humans.
BALANCER_CLIENT_LABEL = "__balancer__"

# Same idea for ``whitelist-front`` chain nodes: the front needs an auth
# UUID on its foreign upstream, the panel keeps that as a Client row
# tagged with this label so it stays invisible to humans.
BYPASS_CLIENT_LABEL = "__bypass__"

WHITELIST_FRONT_MODE = "whitelist-front"
CUSTOM_MODE = "custom"


def is_balancer(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == "balancer"


def is_whitelist_front(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == WHITELIST_FRONT_MODE


def is_custom(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == CUSTOM_MODE


def is_service_client(c: Client) -> bool:
    """Return True if a client is a panel-internal auth row.

    Covers both balancer auth (``__balancer__-<id>``) and whitelist-front
    chain auth (``__bypass__-<id>``).
    """
    label = c.label or ""
    email = c.email or ""
    if label in (BALANCER_CLIENT_LABEL, BYPASS_CLIENT_LABEL):
        return True
    if email.startswith("__balancer__-") or email.startswith("__bypass__-"):
        return True
    return False


def balancer_client_email(balancer_id: int) -> str:
    return f"__balancer__-{balancer_id}"


def bypass_client_email(front_id: int) -> str:
    return f"__bypass__-{front_id}"


def ensure_balancer_upstream_client(
    db: Session, balancer: Server, upstream: Server
) -> tuple[Client, bool]:
    """Make sure a Client row exists on ``upstream`` that ``balancer``
    can dial to authenticate. Idempotent — returns ``(client, created)``
    where ``created`` is ``True`` only when a new row was inserted.
    Caller is expected to commit.

    The ``created`` flag matters because ``push_balancer_config``
    re-pushes every upstream's xray config when this returns, and each
    push restarts xray-core on the node (~10 s of dropped UDP for any
    user connected through it). Only upstreams whose auth set actually
    changed should be re-pushed.
    """
    email = balancer_client_email(balancer.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None:
        return existing, False
    c = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BALANCER_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(c)
    db.flush()
    return c, True


def service_client_email(source_id: int) -> str:
    # Keep the historical prefix so every existing admin/API filter continues
    # to hide these machine credentials from human client lists.
    return f"__balancer__-svc-{source_id}"


def ensure_service_upstream_client(
    db: Session, source: Server, upstream: Server, *, create: bool = True
) -> tuple[Client | None, bool]:
    """Return the private source->upstream credential used for service routes."""

    email = service_client_email(source.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None or not create:
        return existing, False
    client = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BALANCER_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(client)
    db.flush()
    return client, True


def ensure_bypass_upstream_client(
    db: Session, front: Server, upstream: Server
) -> tuple[Client, bool]:
    """Make sure a Client row exists on ``upstream`` that the
    whitelist-front ``front`` can dial. Idempotent — returns
    ``(client, created)`` so the caller can skip a redundant
    upstream re-push when the auth client was already present.
    Caller commits.
    """
    email = bypass_client_email(front.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None:
        return existing, False
    c = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BYPASS_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(c)
    db.flush()
    return c, True


def pool_upstreams(db: Session) -> list[Server]:
    """Servers currently usable as balancer upstreams.

    Returns every node in any auto-balance tier (``primary`` /
    ``fallback``) that exposes a vless+reality endpoint a balancer can
    dial. That includes:

    * ``standalone`` foreign exits (legacy ``in_pool=True`` or explicit
      ``pool_tier='primary'``).
    * ``standalone`` rows tagged ``pool_tier='fallback'`` (regular
      foreign nodes the admin demoted to fallback duty).
    * ``whitelist-front`` chain nodes tagged ``pool_tier='fallback'``
      — from a balancer's perspective the chain's RU-front IP is just
      another vless+reality endpoint; the chain forwards through to
      its own foreign upstream internally. Without this entry the
      auto-balance "fallback bucket" is invisible to balancer clients
      whenever the admin attaches a foreign upstream to the fallback
      node (which flips its mode away from ``standalone``).

    Balancer rows never participate — a balancer can't be its own
    upstream, that would loop.
    """
    rows = db.scalars(
        select(Server)
        .where(Server.mode != "balancer")
        .order_by(Server.id)
    ).all()
    out: list[Server] = []
    for row in rows:
        # The server-side Xray balancer speaks VLESS. A Hysteria 2 QUIC
        # endpoint cannot be used as one of its native VLESS outbounds.
        if is_hysteria2(row) or getattr(row, "protocol", "") == "vless-xhttp-tls":
            continue
        # Use the tier helper so the legacy ``in_pool=True`` rows
        # (which may not have an explicit ``pool_tier`` yet) still
        # land in primary, just like the subscription renderer does.
        if server_pool_tier(row) in (TIER_PRIMARY, TIER_FALLBACK):
            out.append(row)
    return out


def _active_clients_payload(server: Server) -> list[dict]:
    return [
        {"id": c.uuid, "email": c.email, "flow": effective_client_flow(c, server)}
        for c in server.clients
        if c.is_active()
    ]


def _service_routing_payload(
    db: Session,
    source: Server,
    *,
    create_missing: bool,
) -> tuple[list[dict], list[Server]]:
    """Build verified peer payload and optionally provision its credentials."""

    enabled = service_routing_enabled(db)
    excluded = service_routing_excluded_exit_node_ids(db)
    needed = enabled - _ip_region_routing_caps(server_ip_region(source))
    if not needed:
        return [], []
    candidates = db.scalars(
        select(Server)
        .where(Server.mode == "standalone", Server.id != source.id)
        .order_by(Server.id)
    ).all()
    payload: list[dict] = []
    changed: list[Server] = []
    for upstream in candidates:
        if upstream.id in excluded or not _service_exit_ready(upstream):
            continue
        caps = _ip_region_routing_caps(server_ip_region(upstream))
        if not (caps & needed):
            continue
        auth, created = ensure_service_upstream_client(
            db, source, upstream, create=create_missing
        )
        if auth is None:
            continue
        payload.append(
            {
                "id": upstream.id,
                "public_host": upstream.public_host,
                "port": upstream.port,
                "sni": upstream.sni,
                "public_key": upstream.public_key,
                "short_id": upstream.short_id,
                "auth_uuid": auth.uuid,
                "transport": server_transport(upstream),
                "transport_path": server_transport_path(upstream),
                "flow": (
                    "xtls-rprx-vision"
                    if transport_supports_flow(server_transport(upstream))
                    else ""
                ),
                "ip_region": server_ip_region(upstream),
            }
        )
        if created:
            changed.append(upstream)
    return payload, changed


def _live_service_preferences(config: dict) -> dict[str, int]:
    """Recover one existing egress per service without storing credentials."""
    preferences: dict[str, int] = {}
    for service, definition in SERVICE_BALANCERS.items():
        prefix = str(definition["prefix"])
        ids = {
            int(tag[len(prefix):])
            for outbound in config.get("outbounds", [])
            if isinstance(outbound, dict)
            for tag in [str(outbound.get("tag") or "")]
            if tag.startswith(prefix) and tag[len(prefix):].isdigit()
        }
        if len(ids) == 1:
            preferences[service] = ids.pop()
    return preferences


def _push_standalone_config(
    server: Server,
    db: Session | None,
    *,
    create_missing_service_clients: bool,
) -> list[Server]:
    service_upstreams: list[dict] = []
    changed: list[Server] = []
    if db is not None:
        service_upstreams, changed = _service_routing_payload(
            db,
            server,
            create_missing=create_missing_service_clients,
        )
    agent = AgentClient(server.agent_url, server.agent_token)
    preferences = _live_service_preferences(agent.get_config()) if service_upstreams else {}
    proxy_protocol_port = _prepare_bridge_proxy_ingress(agent, db, server)
    config = build_config(
        source_server_id=server.id,
        port=server.port,
        server_names=server_all_snis(server),
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        transport=server_transport(server),
        transport_path=server_transport_path(server),
        warp_enabled=bool(getattr(server, "warp_enabled", False)),
        warp_domains=server_warp_domains(server),
        service_upstreams=service_upstreams,
        local_ip_region=server_ip_region(server),
        service_routing_services=(service_routing_enabled(db) if db is not None else None),
        preferred_service_upstreams=preferences,
        proxy_protocol_port=proxy_protocol_port,
    )
    # CDN endpoints share this agent. Preserve their independently managed
    # loopback inbounds whenever the source Reality node is rebuilt.
    if db is not None:
        siblings = db.scalars(select(Server).where(Server.agent_url == server.agent_url)).all()
        tags = {n.custom_inbound_tag for n in siblings
                if n.id != server.id and n.protocol == "vless-xhttp-tls" and n.mode == "custom"}
        if tags:
            live = agent.get_config()
            config["inbounds"].extend(i for i in live.get("inbounds", []) if i.get("tag") in tags)
    _apply_server_torrent_policy(config, server, db)
    agent.put_config(config)
    return changed


def push_standalone_config(server: Server, db: Session | None = None) -> None:
    """Build + push a regular Reality VLESS config for ``server``.

    Service clients (panel-managed balancer auth rows) are included
    alongside real user clients — xray accepts both, admins just don't
    see the service ones in the UI.
    """
    changed = _push_standalone_config(
        server,
        db,
        create_missing_service_clients=db is not None,
    )
    if db is None or not changed:
        return
    db.commit()
    # The target must accept the newly-created machine UUID before the source
    # can use it. Rebuild it without recursively provisioning another graph.
    for upstream in changed:
        db.refresh(upstream)
        _push_standalone_config(
            upstream,
            db,
            create_missing_service_clients=False,
        )


def push_hysteria_config(server: Server) -> None:
    """Build and atomically deploy a Hysteria 2 config through the agent."""
    if (getattr(server, "mode", "") or "standalone") != "standalone":
        raise AgentError("Hysteria 2 nodes support standalone mode only")
    if bool(getattr(server, "warp_enabled", False)):
        raise AgentError("WARP routing is not supported on Hysteria 2 nodes")
    config = build_hysteria_config(
        port=server.port,
        listen=getattr(server, "hysteria_listen", "") or "",
        sni=server.sni,
        tls_mode=getattr(server, "hysteria_tls_mode", "acme") or "acme",
        acme_email=getattr(server, "hysteria_acme_email", "") or "",
        cert_path=getattr(server, "hysteria_cert_path", "") or "",
        key_path=getattr(server, "hysteria_key_path", "") or "",
        clients=[
            {"email": c.email, "password": c.uuid}
            for c in server.clients
            if c.is_active() and not is_service_client(c)
        ],
        auth_mode=getattr(server, "hysteria_auth_mode", "userpass") or "userpass",
        auth_password=getattr(server, "hysteria_auth_password", "") or "",
        stats_secret=getattr(server, "hysteria_stats_secret", "") or "",
        stats_port=int(getattr(server, "hysteria_stats_port", 9999) or 9999),
        obfs_type=getattr(server, "hysteria_obfs_type", "") or "",
        obfs_password=getattr(server, "hysteria_obfs_password", "") or "",
        up_mbps=int(getattr(server, "hysteria_up_mbps", 0) or 0),
        down_mbps=int(getattr(server, "hysteria_down_mbps", 0) or 0),
        ignore_client_bandwidth=bool(
            getattr(server, "hysteria_ignore_client_bandwidth", False)
        ),
        congestion=getattr(server, "hysteria_congestion", "bbr") or "bbr",
        bbr_profile=getattr(server, "hysteria_bbr_profile", "standard")
        or "standard",
        disable_udp=bool(getattr(server, "hysteria_disable_udp", False)),
        udp_idle_timeout_seconds=int(
            getattr(server, "hysteria_udp_idle_timeout", 60) or 60
        ),
        masquerade_url=getattr(server, "hysteria_masquerade_url", "") or "",
        advanced_json=getattr(server, "hysteria_advanced_json", "") or "",
    )
    if not bool(getattr(server, "torrent_allowed", False)):
        acl = config.setdefault("acl", {})
        if acl.get("file"):
            raise AgentError("cannot combine torrent guard with file-based Hysteria ACL")
        existing = list(acl.get("inline") or [])
        guards = [
            "reject(all, tcp/6881-6889)",
            "reject(all, udp/6881-6889)",
            "reject(all, tcp/51413)",
            "reject(all, udp/51413)",
        ]
        acl["inline"] = guards + [rule for rule in existing if rule not in guards]
    AgentClient(server.agent_url, server.agent_token).put_hysteria_config(config)


def push_vless_ws_tls_config(server: Server) -> None:
    """Deploy only the loopback VLESS/WS Xray configuration.

    External TLS is deliberately outside of panel control.  This function
    never provisions certificates, changes nginx/Caddy, or opens a public
    Xray listener.
    """
    if (getattr(server, "mode", "") or "standalone") != "standalone":
        raise AgentError("VLESS WS/TLS nodes support standalone mode only")
    if bool(getattr(server, "warp_enabled", False)):
        raise AgentError("WARP routing is not supported on VLESS WS/TLS nodes")
    config = build_vless_ws_tls_config(
        ws_port=int(getattr(server, "ws_inbound_port", 5443) or 5443),
        ws_path=server_transport_path(server),
        clients=_active_clients_payload(server),
    )
    _apply_server_torrent_policy(config, server, None)
    AgentClient(server.agent_url, server.agent_token).put_config(config)


@_serialized_custom_config
def push_custom_config(
    server: Server,
    db: Session | None = None,
    *,
    remove_emails: Iterable[str] = (),
    reconcile_warp: bool = False,
) -> None:
    """Reconcile panel-owned users inside one externally-owned inbound.

    Unknown users are preserved. The panel changes ``settings.clients`` on
    ``custom_inbound_tag`` and, only when explicitly enabled/disabled, its own
    ``warp-out`` outbound + routing rule. Every other structural field stays
    externally owned. The agent applies a pure user delta through xray's
    runtime API; changing WARP is structural and therefore restarts xray.
    """
    tag = (getattr(server, "custom_inbound_tag", "") or "").strip()
    if not tag:
        raise AgentError("custom node has no inbound tag")
    agent = AgentClient(server.agent_url, server.agent_token)
    try:
        config = agent.get_config()
    except AgentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AgentError(f"could not read custom config: {exc}") from exc
    target: dict | None = None
    for inbound in config.get("inbounds") or []:
        if str(inbound.get("tag") or "") == tag:
            target = inbound
            break
    if target is None:
        raise AgentError(f"custom inbound {tag!r} no longer exists on the node")
    if str(target.get("protocol") or "").lower() != "vless":
        raise AgentError(f"custom inbound {tag!r} is not VLESS")

    if getattr(server, "protocol", "") == "vless-xhttp-tls":
        extra = json.loads(getattr(server, "xhttp_extra_json", "") or "{}")
        xhttp = dict(extra)
        xhttp.setdefault("path", server_transport_path(server))
        xhttp.setdefault("mode", "packet-up")
        # Keep supported standard keys at the transport level and in extra.
        xhttp["extra"] = extra
        target.setdefault("streamSettings", {})["xhttpSettings"] = xhttp
    settings = target.setdefault("settings", {})
    current = list(settings.get("clients") or [])
    managed = {c.email: c for c in server.clients}
    remove = {str(email) for email in remove_emails if email}
    emitted: set[str] = set()
    next_clients: list[dict] = []

    for raw in current:
        email = str(raw.get("email") or "")
        if email in remove:
            continue
        panel_client = managed.get(email)
        if panel_client is None:
            next_clients.append(raw)
            continue
        emitted.add(email)
        if panel_client.is_active():
            next_clients.append(
                {
                    "id": panel_client.uuid,
                    "email": panel_client.email,
                    "flow": effective_client_flow(panel_client, server),
                }
            )

    for email, panel_client in managed.items():
        if email in emitted or email in remove or not panel_client.is_active():
            continue
        next_clients.append(
            {
                "id": panel_client.uuid,
                "email": panel_client.email,
                "flow": effective_client_flow(panel_client, server),
            }
        )
    settings["clients"] = next_clients
    # During a transport migration keep the old entry usable, with the same
    # additions, expiry/disable decisions and removals as the new entry.
    sync_tags = json.loads(getattr(server, "custom_sync_tags_json", "[]") or "[]")
    for sync_tag in sync_tags:
        if sync_tag == tag:
            continue
        legacy = next((i for i in config.get("inbounds", []) if i.get("tag") == sync_tag), None)
        if legacy is None or legacy.get("protocol") != "vless":
            raise AgentError(f"migration inbound {sync_tag!r} missing or not VLESS")
        legacy_settings = legacy.setdefault("settings", {})
        unmanaged = [r for r in legacy_settings.get("clients", [])
                     if r.get("email") not in managed and r.get("email") not in remove]
        stream = legacy.get("streamSettings", {})
        vision = stream.get("network", "tcp") in {"tcp", "raw"} and stream.get("security") == "reality"
        legacy_settings["clients"] = unmanaged + [
            {"id": c.uuid, "email": c.email, "flow": (c.flow or "xtls-rprx-vision") if vision else ""}
            for email, c in managed.items() if email not in remove and c.is_active()
        ]
    # Client CRUD must preserve the live routing graph on shared hosts.
    # Sibling panel records may have different WARP preferences: applying
    # each record's preferences on every client change flips the graph and
    # restarts the common Xray process. Reconcile only for explicit settings.
    if reconcile_warp:
        outbounds = config.setdefault("outbounds", [])
        routing = config.setdefault("routing", {})
        if not isinstance(routing, dict):
            raise AgentError("custom config routing must be an object")
        routing_rules = routing.setdefault("rules", [])
        if not isinstance(outbounds, list) or not isinstance(routing_rules, list):
            raise AgentError("custom config outbounds/routing.rules must be arrays")
        try:
            apply_warp_config(
                outbounds,
                routing_rules,
                enabled=bool(getattr(server, "warp_enabled", False)),
                domains=server_warp_domains(server),
            )
        except ValueError as exc:
            raise AgentError(str(exc)) from exc
    try:
        _apply_server_torrent_policy(config, server, db)
        agent.put_config(config)
    except AgentError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise AgentError(f"could not update custom inbound: {exc}") from exc


def custom_inbound_client_emails(server: Server) -> set[str]:
    """Return existing emails so imports never overwrite external users."""
    tag = (getattr(server, "custom_inbound_tag", "") or "").strip()
    try:
        config = AgentClient(server.agent_url, server.agent_token).get_config()
    except Exception as exc:  # noqa: BLE001
        raise AgentError(f"could not read custom config: {exc}") from exc
    for inbound in config.get("inbounds") or []:
        if str(inbound.get("tag") or "") != tag:
            continue
        clients = (inbound.get("settings") or {}).get("clients") or []
        return {str(client.get("email") or "") for client in clients if client.get("email")}
    raise AgentError(f"custom inbound {tag!r} no longer exists on the node")


def push_balancer_config(server: Server, db: Session) -> None:
    """Build + push a balancer config for ``server`` (``mode='balancer'``).

    Walks current pool membership, ensures each upstream has an auth
    client for this balancer (creating missing rows on-the-fly) and
    re-pushes each upstream's xray config so it accepts the new UUID,
    then builds the balancer's own xray config with observatory +
    ``routing.balancers`` ``leastLoad`` (primary tier preferred via
    cost penalty on the ``pool-fb-`` prefix; fallback only takes over
    when every primary fails its observatory probe).

    If the pool is empty, the balancer still accepts users but routes
    them direct via ``freedom`` — the admin will notice the
    ``pool members: 0`` badge and flip ``in_pool`` on a standalone
    node.
    """
    excluded_service_nodes = service_routing_excluded_exit_node_ids(db)
    upstreams_rows = pool_upstreams(db)
    upstreams_payload: list[dict] = []
    upstreams_to_push: list[Server] = []
    for up in upstreams_rows:
        auth, created = ensure_balancer_upstream_client(db, server, up)
        # ``tier`` drives the outbound tag prefix in
        # ``build_balancer_config`` — fallback rows get the
        # ``pool-fb-<id>`` prefix so the balancer's leastLoad cost
        # rule down-ranks them and primary tier always wins while
        # alive.
        upstreams_payload.append(
            {
                "id": up.id,
                "public_host": up.public_host,
                "port": up.port,
                "sni": up.sni,
                "public_key": up.public_key,
                "short_id": up.short_id,
                "auth_uuid": auth.uuid,
                "tier": server_pool_tier(up),
                # Carry the upstream's transport so the balancer's outbound
                # speaks the same network as the upstream's inbound — xray
                # refuses to handshake when these disagree.
                "transport": server_transport(up),
                "transport_path": server_transport_path(up),
                "protocol": str(getattr(up, "protocol", "") or "vless-reality"),
                # Force-empty flow on grpc / xhttp upstreams; xray-core
                # rejects vision on multiplexed transports.
                "flow": (
                    "xtls-rprx-vision"
                    if transport_supports_flow(server_transport(up))
                    else ""
                ),
                "ip_region": server_ip_region(up),
                "service_routing_exit_excluded": (
                    up.id in excluded_service_nodes or not _service_exit_ready(up)
                ),
            }
        )
        # Only re-push upstreams whose user set actually changed (we
        # just inserted a new auth row). Each upstream push restarts
        # xray on that node, so unconditionally re-pushing every pool
        # member on every balancer push amplified routine balancer
        # changes into N user-visible 10 s drops.
        if created:
            upstreams_to_push.append(up)
    # Commit any newly-created auth clients before we push, so the
    # upstream agents see them too.
    db.commit()
    for up in upstreams_to_push:
        db.refresh(up)
        # Mode-aware push so a whitelist-front upstream stays in
        # whitelist-front mode (re-running ``push_standalone_config``
        # on it would erase its bypass routing and downgrade it to a
        # plain foreign exit). ``push_config`` dispatches by mode —
        # standalone → ``push_standalone_config``, whitelist-front →
        # ``push_whitelist_front_config`` — and the latter happens to
        # also re-push the *front's own* upstream (lt.xanka.best
        # etc.), which is harmless when that upstream is also in the
        # balancer pool: the second push is idempotent.
        push_config(up, db)

    agent = AgentClient(server.agent_url, server.agent_token)
    proxy_protocol_port = _prepare_bridge_proxy_ingress(agent, db, server)
    config = build_balancer_config(
        port=server.port,
        server_names=server_all_snis(server),
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        upstreams=upstreams_payload,
        transport=server_transport(server),
        transport_path=server_transport_path(server),
        warp_enabled=bool(getattr(server, "warp_enabled", False)),
        warp_domains=server_warp_domains(server),
        service_routing_services=service_routing_enabled(db),
        proxy_protocol_port=proxy_protocol_port,
    )
    _apply_server_torrent_policy(config, server, db)
    agent.put_config(config)


def push_whitelist_front_config(server: Server, db: Session) -> None:
    """Build + push a config for ``server`` (``mode='whitelist-front'``).

    Looks up the foreign ``upstream_server_id``, ensures the panel-managed
    ``__bypass__-<front_id>`` Client row exists on it, re-pushes the
    upstream's config so the new auth UUID lands in xray, then builds
    the front's own config with one VLESS+Reality outbound dialing the
    upstream + a single routing rule that funnels every user packet
    into that outbound.

    When ``upstream_server_id`` is unset / dangling, the front still
    accepts users but routes them ``freedom`` from the front itself —
    the UI shows ``upstream: —`` so the admin notices.
    """
    upstream_id = getattr(server, "upstream_server_id", None)
    upstream: Server | None = None
    upstream_payload: dict | None = None
    if upstream_id:
        upstream = db.get(Server, upstream_id)
        # Refuse to chain into another chain — that would loop or fan
        # out endlessly. Only standalone nodes can be foreign exits.
        if upstream is not None and (
            getattr(upstream, "mode", "") or "standalone"
        ) != "standalone":
            log.warning(
                "whitelist-front %d points at non-standalone upstream %d "
                "(mode=%r) — degrading to direct egress",
                server.id, upstream.id, upstream.mode,
            )
            upstream = None
    if upstream is not None:
        auth, created = ensure_bypass_upstream_client(db, server, upstream)
        upstream_payload = {
            "id": upstream.id,
            "public_host": upstream.public_host,
            "port": upstream.port,
            "sni": upstream.sni,
            "public_key": upstream.public_key,
            "short_id": upstream.short_id,
            "auth_uuid": auth.uuid,
            # Mirror the foreign upstream's transport so this front's
            # outbound matches its inbound shape. Same caveat as the
            # balancer payload: grpc / xhttp upstreams force flow="".
            "transport": server_transport(upstream),
            "transport_path": server_transport_path(upstream),
            "flow": (
                "xtls-rprx-vision"
                if transport_supports_flow(server_transport(upstream))
                else ""
            ),
        }
        # Commit the new auth row before we push so the upstream sees it.
        db.commit()
        # Only re-push the upstream when we actually changed its user
        # set (newly-inserted bypass auth client). Otherwise the
        # upstream's xray config is already in sync and re-pushing
        # would trigger a needless ``systemctl restart xray`` on the
        # foreign node, dropping every user connected through it.
        if created:
            db.refresh(upstream)
            push_config(upstream, db)

    agent = AgentClient(server.agent_url, server.agent_token)
    proxy_protocol_port = _prepare_bridge_proxy_ingress(agent, db, server)
    config = build_whitelist_front_config(
        port=server.port,
        server_names=server_all_snis(server),
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        upstream=upstream_payload,
        transport=server_transport(server),
        transport_path=server_transport_path(server),
        warp_enabled=bool(getattr(server, "warp_enabled", False)),
        warp_domains=server_warp_domains(server),
        proxy_protocol_port=proxy_protocol_port,
    )
    _apply_server_torrent_policy(config, server, db)
    agent.put_config(config)


def push_config(
    server: Server,
    db: Session | None = None,
    *,
    remove_emails: Iterable[str] = (),
    reconcile_warp: bool = False,
) -> None:
    """Push the right xray config for ``server`` based on its ``mode``.

    Balancer and whitelist-front pushes require a DB session so the
    panel can enumerate / resolve upstreams. Pass ``db`` whenever the
    caller has one.
    """
    if is_hysteria2(server):
        push_hysteria_config(server)
    elif is_custom(server):
        push_custom_config(
            server,
            db,
            remove_emails=remove_emails,
            reconcile_warp=reconcile_warp,
        )
    elif is_vless_ws_tls(server):
        push_vless_ws_tls_config(server)
    elif is_balancer(server):
        if db is None:
            raise RuntimeError(
                "balancer push requires a DB session — caller must pass db= "
                "so we can enumerate pool upstreams"
            )
        push_balancer_config(server, db)
    elif is_whitelist_front(server):
        if db is None:
            raise RuntimeError(
                "whitelist-front push requires a DB session — caller must "
                "pass db= so we can resolve upstream_server_id"
            )
        push_whitelist_front_config(server, db)
    else:
        push_standalone_config(server, db)


def rebuild_balancer_configs(db: Session) -> list[tuple[Server, Exception]]:
    """Rebuild every balancer's xray config from the current pool set.

    Called from code paths that change which servers are pool members
    or that rotate an upstream's Reality keys. Per-balancer errors are
    collected so one failing balancer doesn't block others.
    """
    errors: list[tuple[Server, Exception]] = []
    for bal in db.scalars(select(Server).where(Server.mode == "balancer")).all():
        try:
            push_balancer_config(bal, db)
        except Exception as exc:  # noqa: BLE001
            errors.append((bal, exc))
            log.warning("balancer push failed for server=%d: %s", bal.id, exc)
    return errors


def rebuild_service_routing_configs(db: Session) -> list[tuple[Server, Exception]]:
    """Provision the complete capability graph, then push each node once."""

    sources = [
        server
        for server in db.scalars(
            select(Server).where(Server.mode == "standalone").order_by(Server.id)
        ).all()
        if not is_hysteria2(server)
    ]
    for source in sources:
        _service_routing_payload(db, source, create_missing=True)
    db.commit()

    errors: list[tuple[Server, Exception]] = []
    for source in sources:
        source_id = source.id
        source_name = source.name
        try:
            db.refresh(source)
            _push_standalone_config(
                source,
                db,
                create_missing_service_clients=False,
            )
        except Exception as exc:  # noqa: BLE001
            errors.append((source, exc))
            # The admin may delete a node while a long fleet rebuild is
            # running. Accessing expired ORM attributes after that deletion
            # raises ObjectDeletedError and used to abort the whole rebuild.
            log.warning(
                "service routing push failed for server=%d name=%s: %s",
                source_id,
                source_name,
                exc,
            )
    return errors


def delete_balancer_auth_clients(db: Session, balancer_id: int) -> list[Server]:
    """Remove every ``__balancer__-<id>`` auth client on all upstreams
    when a balancer node is deleted. Returns the list of affected
    upstream Server rows so the caller can re-push their configs.
    """
    email = balancer_client_email(balancer_id)
    affected: list[Server] = []
    rows = list(db.scalars(select(Client).where(Client.email == email)).all())
    for row in rows:
        up = db.get(Server, row.server_id)
        if up is not None:
            affected.append(up)
        db.delete(row)
    db.commit()
    return affected


def delete_bypass_auth_clients(db: Session, front_id: int) -> list[Server]:
    """Remove every ``__bypass__-<id>`` auth client on the upstream
    when a whitelist-front node is deleted. Symmetric to
    ``delete_balancer_auth_clients``. Returns affected upstream rows
    so the caller can re-push their configs.
    """
    email = bypass_client_email(front_id)
    affected: list[Server] = []
    rows = list(db.scalars(select(Client).where(Client.email == email)).all())
    for row in rows:
        up = db.get(Server, row.server_id)
        if up is not None:
            affected.append(up)
        db.delete(row)
    db.commit()
    return affected


def delete_service_auth_clients(db: Session, source_id: int) -> list[Server]:
    """Remove per-node capability-routing credentials for a deleted source."""

    email = service_client_email(source_id)
    affected: list[Server] = []
    rows = list(db.scalars(select(Client).where(Client.email == email)).all())
    for row in rows:
        upstream = db.get(Server, row.server_id)
        if upstream is not None:
            affected.append(upstream)
        db.delete(row)
    db.commit()
    return affected


def rebuild_whitelist_front_configs(
    db: Session,
    *,
    only_upstream_id: int | None = None,
) -> list[tuple[Server, Exception]]:
    """Rebuild every whitelist-front's xray config.

    Called when an upstream's Reality keys / inbound settings change so
    the chained fronts re-dial with the new credentials. Pass
    ``only_upstream_id`` to only refresh fronts that point at one
    specific upstream (e.g. after rotating that upstream's keys).
    """
    errors: list[tuple[Server, Exception]] = []
    q = select(Server).where(Server.mode == WHITELIST_FRONT_MODE)
    if only_upstream_id is not None:
        q = q.where(Server.upstream_server_id == only_upstream_id)
    for front in db.scalars(q).all():
        try:
            push_whitelist_front_config(front, db)
        except Exception as exc:  # noqa: BLE001
            errors.append((front, exc))
            log.warning(
                "whitelist-front push failed for server=%d: %s", front.id, exc
            )
    return errors


__all__ = [
    "BALANCER_CLIENT_LABEL",
    "BYPASS_CLIENT_LABEL",
    "WHITELIST_FRONT_MODE",
    "AgentError",
    "balancer_client_email",
    "bypass_client_email",
    "custom_inbound_client_emails",
    "delete_balancer_auth_clients",
    "delete_bypass_auth_clients",
    "delete_service_auth_clients",
    "ensure_balancer_upstream_client",
    "ensure_bypass_upstream_client",
    "is_balancer",
    "is_custom",
    "is_service_client",
    "is_whitelist_front",
    "pool_upstreams",
    "push_balancer_config",
    "push_config",
    "push_hysteria_config",
    "push_standalone_config",
    "push_whitelist_front_config",
    "rebuild_balancer_configs",
    "rebuild_service_routing_configs",
    "rebuild_whitelist_front_configs",
    "service_routing_enabled",
    "service_routing_excluded_exit_node_ids",
    "service_routing_snapshot",
    "set_service_routing_enabled",
    "set_service_routing_node_enabled",
]

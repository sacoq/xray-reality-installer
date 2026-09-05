"""Build xray-core config.json from our data model.

Shared between panel (generates config to push) and agent (writes it).
"""
from __future__ import annotations

import os
from typing import Any


# Stats / API port used by the local xray instance (localhost-only).
XRAY_API_PORT = 10085
PROXY_PROTOCOL_INBOUND_TAG = "vless-reality-proxy"

# Xray's per-user StatsService has byte counters but does not expose the
# source address of a connection.  The node anti-sharing sensor consumes the
# access stream from tmpfs and immediately aggregates it in RAM.  Nothing is
# written to persistent storage, and the agent bounds/truncates this file.
XRAY_ACCESS_LOG_PATH = "/dev/shm/xnpanel-xray-access.log"


def build_log_config() -> dict[str, Any]:
    return {
        "loglevel": "warning",
        "access": XRAY_ACCESS_LOG_PATH,
    }

# Panel-managed Cloudflare WARP outbound. The tag is intentionally stable so
# custom-node configs can be reconciled idempotently as the admin toggles WARP
# on and off.
WARP_OUTBOUND_TAG = "warp-out"
WARP_INTERFACE = "warp"
GEMINI_EGRESS_OUTBOUND_TAG = "gemini-egress"
GEMINI_EGRESS_HOST = os.environ.get("GEMINI_EGRESS_HOST", "").strip()
GEMINI_EGRESS_PORT = int(os.environ.get("GEMINI_EGRESS_PORT", "15443") or 15443)

# Google evaluates both the Gemini page and its auth/static/API requests. They
# must share one stable egress; otherwise account country/anti-abuse checks see
# an impossible location change inside a single page load.
GEMINI_EGRESS_DOMAINS = [
    # Keep this deliberately narrow: Search, YouTube, Gmail and unrelated
    # Google APIs must continue to use the node's normal routing.  These are
    # Gemini frontends and private backends observed in its web/app flows.
    "geosite:google-gemini",
    "full:gemini.google.com",
    "full:gemini.google",
    "full:bard.google.com",
    "full:aistudio.google.com",
    "full:makersuite.google.com",
    "full:ai.google.dev",
    "full:geller-pa.googleapis.com",
    "full:generativelanguage.googleapis.com",
    "full:proactivebackend-pa.googleapis.com",
    "full:robinfrontend-pa.googleapis.com",
    "full:aisandbox-pa.googleapis.com",
]

# Suggested per-node domain list from the WARP integration request. Every node
# stores its own copy and can freely replace it in the UI/API.
DEFAULT_WARP_DOMAINS = [
    # Keep Gemini's authenticated web flow on one egress. Routing only the
    # visible gemini.google.com page while Google auth/API/static requests go
    # direct leaks the user's real region and produces a false "unsupported in
    # your country" result even though WARP itself is healthy.
    "domain:google.com",
    "domain:googleapis.com",
    "domain:gstatic.com",
    "domain:googleusercontent.com",
    "domain:ggpht.com",
    "domain:withgoogle.com",
    "domain:google.dev",
    "domain:google",
    "domain:goog",
    "geosite:google-gemini",
    "domain:deepmind.com",
    "domain:deepmind.google",
    "domain:geller-pa.googleapis.com",
    "domain:generativelanguage.googleapis.com",
    "domain:proactivebackend-pa.googleapis.com",
    "domain:ai.google.dev",
    "domain:generativeai.google",
    "domain:makersuite.google.com",
    "domain:aistudio.google.com",
    "domain:bard.google.com",
    "domain:gemini.google",
    "domain:gemini.google.com",
    "domain:notebooklm.google.com",
    "domain:clients6.google.com",
    "domain:notebooklm.google",
    "domain:jules.google",
    "domain:jules.google.com",
    "domain:labs.google",
    "domain:aisandbox-pa.googleapis.com",
    "domain:stitch.withgoogle.com",
    "domain:robinfrontend-pa.googleapis.com",
    "domain:aida.googleapis.com",
    "domain:antigravity-pa.googleapis.com",
    "domain:antigravity.googleapis.com",
    "domain:antigravity.google",
    "domain:antigravity-unleash.goog",
    "domain:firebaseinstallations.googleapis.com",
    "domain:speechs3proto2-pa.googleapis.com",
]


def normalise_warp_domains(domains: list[str] | None) -> list[str]:
    """Clean, de-duplicate and validate an Xray domain matcher list."""
    out: list[str] = []
    seen: set[str] = set()
    for raw in domains or []:
        value = str(raw).strip()
        if not value or value in seen:
            continue
        if len(value) > 512 or any(ch.isspace() for ch in value):
            raise ValueError(f"invalid WARP domain matcher: {value!r}")
        out.append(value)
        seen.add(value)
    if len(out) > 256:
        raise ValueError("at most 256 WARP domain matchers are allowed")
    return out


def build_warp_outbound() -> dict[str, Any]:
    return {
        "tag": WARP_OUTBOUND_TAG,
        "protocol": "freedom",
        "settings": {"domainStrategy": "UseIP"},
        "streamSettings": {
            "sockopt": {
                "interface": WARP_INTERFACE,
                "tcpFastOpen": True,
            }
        },
    }


def build_gemini_egress_outbound() -> dict[str, Any]:
    return {
        "tag": GEMINI_EGRESS_OUTBOUND_TAG,
        "protocol": "socks",
        "settings": {
            "servers": [
                {
                    "address": GEMINI_EGRESS_HOST,
                    "port": GEMINI_EGRESS_PORT,
                }
            ],
        },
    }


def apply_warp_config(
    outbounds: list[dict[str, Any]],
    routing_rules: list[dict[str, Any]],
    *,
    enabled: bool,
    domains: list[str] | None,
    gemini_egress_enabled: bool = True,
) -> None:
    """Reconcile the panel-managed WARP outbound and first routing rule.

    This also works for externally-owned/custom configs: unrelated outbounds
    and rules keep their order and contents.
    """
    outbounds[:] = [
        item for item in outbounds
        if str(item.get("tag") or "")
        not in {WARP_OUTBOUND_TAG, GEMINI_EGRESS_OUTBOUND_TAG}
    ]
    routing_rules[:] = [
        item for item in routing_rules
        if str(item.get("outboundTag") or "")
        not in {WARP_OUTBOUND_TAG, GEMINI_EGRESS_OUTBOUND_TAG}
        and not (
            str(item.get("outboundTag") or "") == "blocked"
            and str(item.get("network") or "") == "udp"
            and list(item.get("domain") or []) == GEMINI_EGRESS_DOMAINS
        )
    ]
    if enabled:
        cleaned = normalise_warp_domains(domains)
        if not cleaned:
            raise ValueError("WARP is enabled but its domain list is empty")
        # The WARP rule must win over balancer/whitelist catch-alls.
        outbounds.insert(0, build_warp_outbound())
        routing_rules.insert(
            0,
            {
                "type": "field",
                "domain": cleaned,
                "outboundTag": WARP_OUTBOUND_TAG,
            },
        )

    if GEMINI_EGRESS_HOST and gemini_egress_enabled:
        if not 1 <= GEMINI_EGRESS_PORT <= 65535:
            raise ValueError("GEMINI_EGRESS_PORT must be between 1 and 65535")
        if not any(str(item.get("tag") or "") == "blocked" for item in outbounds):
            outbounds.append({"tag": "blocked", "protocol": "blackhole"})
        outbounds.insert(0, build_gemini_egress_outbound())
        # QUIC cannot use the TCP-only authenticated SOCKS path. Reject it
        # immediately so browsers retry Gemini over TCP without leaking via a
        # different egress.
        routing_rules.insert(
            0,
            {
                "type": "field",
                "domain": list(GEMINI_EGRESS_DOMAINS),
                "network": "udp",
                "outboundTag": "blocked",
            },
        )
        routing_rules.insert(
            0,
            {
                "type": "field",
                "domain": list(GEMINI_EGRESS_DOMAINS),
                "network": "tcp",
                "outboundTag": GEMINI_EGRESS_OUTBOUND_TAG,
            },
        )


# Reality stream transports we know how to render. Anything outside of
# this set is rejected by the API layer before it ever reaches the
# config builder. ``tcp`` is the historical default; ``grpc`` and
# ``xhttp`` are the multiplexed HTTP/2 variants — both refuse the
# ``xtls-rprx-vision`` flow at xray-core level, so the builder zeroes
# out client flow when transport != tcp.
TRANSPORT_TCP = "tcp"
TRANSPORT_GRPC = "grpc"
TRANSPORT_XHTTP = "xhttp"


def _build_stream_settings(
    *,
    transport: str,
    transport_path: str,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
) -> dict[str, Any]:
    """Return the ``streamSettings`` block for the user-facing inbound.

    Reality config (security/realitySettings) is identical across
    transports — it only depends on dest / serverNames / keys. The
    differences are in ``network`` + the per-transport sub-block
    (``tcpSettings`` / ``grpcSettings`` / ``xhttpSettings``).
    """
    t = (transport or TRANSPORT_TCP).lower()
    reality = {
        "security": "reality",
        "realitySettings": {
            "show": False,
            "dest": dest,
            "xver": 0,
            "serverNames": list(server_names),
            "privateKey": private_key,
            "shortIds": short_ids,
        },
    }
    if t == TRANSPORT_GRPC:
        # serviceName is the gRPC path; clients must use the exact same
        # string. ``multiMode`` is left at xray-core's default (false) so
        # older v2rayN / Hiddify builds that don't speak multi keep
        # connecting.
        service_name = (transport_path or "").strip() or "apisub"
        return {
            "network": "grpc",
            "grpcSettings": {"serviceName": service_name},
            **reality,
        }
    if t == TRANSPORT_XHTTP:
        path = (transport_path or "").strip() or "/sub"
        # ``mode: "auto"`` lets xray-core pick between packet-up /
        # stream-up; matches what the official xhttp docs suggest as
        # the default. ``host`` is left to xray-core (it falls back to
        # the SNI).
        return {
            "network": "xhttp",
            "xhttpSettings": {"path": path, "mode": "auto"},
            **reality,
        }
    # tcp (default)
    return {
        "network": "tcp",
        "tcpSettings": {
            "keepAliveInterval": 30,
            "keepAliveIdle": 60,
            "header": {"type": "none"},
        },
        "sockopt": {
            "tcpFastOpen": True,
            "tcpKeepAlive": True,
        },
        **reality,
    }


def build_inbound(
    *,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    tag: str = "vless-reality",
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
    accept_proxy_protocol: bool = False,
) -> dict[str, Any]:
    """Build the VLESS+Reality inbound.

    ``server_names`` is the full list of SNIs the inbound accepts; the
    first one is treated as the "primary" / default and is what the
    panel uses when a client doesn't pin a specific SNI of its own.
    All other entries let admins serve different keys with different
    SNIs from the same inbound (helpful when a single SNI starts
    getting DPI-flagged on a mobile operator).

    Each client dict must have: id (uuid), email, flow (default xtls-rprx-vision).
    When ``transport`` is grpc/xhttp the per-client ``flow`` is zeroed
    out — xray-core rejects ``xtls-rprx-vision`` on multiplexed
    transports.
    """
    if not server_names:
        raise ValueError("build_inbound requires at least one serverName")

    t = (transport or TRANSPORT_TCP).lower()
    use_flow = t == TRANSPORT_TCP

    inbound_clients: list[dict[str, Any]] = []
    for c in clients:
        entry = {
            "id": c["id"],
            "flow": (c.get("flow", "xtls-rprx-vision") if use_flow else ""),
            "email": c["email"],
        }
        inbound_clients.append(entry)

    stream = _build_stream_settings(
        transport=t,
        transport_path=transport_path,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
    )
    if accept_proxy_protocol:
        # Xray treats PROXY protocol as required when this flag is enabled,
        # therefore it must live on a dedicated listener.  Keeping the normal
        # inbound untouched preserves direct client connections.
        sockopt = stream.setdefault("sockopt", {})
        sockopt["acceptProxyProtocol"] = True

    return {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": inbound_clients,
            "decryption": "none",
        },
        "streamSettings": stream,
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        },
    }


def attach_proxy_protocol_inbound(
    config: dict[str, Any],
    *,
    port: int | None,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
) -> dict[str, Any]:
    """Attach a bridge-only VLESS listener that requires PROXY protocol v2.

    The regular public listener remains unchanged.  Every routing rule that
    explicitly targets the public inbound is extended to the bridge inbound
    so server-side IP-region routing and WARP behavior remain identical.
    """

    if port is None:
        return config
    proxy_port = int(port)
    if not 1 <= proxy_port <= 65535:
        raise ValueError("proxy protocol port must be between 1 and 65535")
    inbounds = config.setdefault("inbounds", [])
    inbounds.append(
        build_inbound(
            port=proxy_port,
            server_names=server_names,
            dest=dest,
            private_key=private_key,
            short_ids=short_ids,
            clients=clients,
            tag=PROXY_PROTOCOL_INBOUND_TAG,
            transport=transport,
            transport_path=transport_path,
            accept_proxy_protocol=True,
        )
    )
    rules = ((config.get("routing") or {}).get("rules") or [])
    for rule in rules:
        tags = rule.get("inboundTag")
        if (
            isinstance(tags, list)
            and "vless-reality" in tags
            and PROXY_PROTOCOL_INBOUND_TAG not in tags
        ):
            tags.append(PROXY_PROTOCOL_INBOUND_TAG)
    return config


def build_api_inbound() -> dict[str, Any]:
    """Expose xray's gRPC API on localhost for stats / runtime control."""
    return {
        "tag": "api",
        "listen": "127.0.0.1",
        "port": XRAY_API_PORT,
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }


def build_vless_ws_tls_config(
    *,
    ws_port: int,
    ws_path: str,
    clients: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build a VLESS/WS listener for an externally terminated TLS vhost.

    The public domain, certificate and reverse proxy are intentionally absent
    from this file.  The reverse proxy must forward its TLS WS route to
    ``127.0.0.1:ws_port``.  Keeping the listener loopback-only prevents a
    plaintext VLESS/WS endpoint from being exposed accidentally.
    """
    port = int(ws_port)
    if not 1 <= port <= 65535:
        raise ValueError("WS inbound port must be between 1 and 65535")
    path = (ws_path or "/").strip() or "/"
    if not path.startswith("/"):
        raise ValueError("WS path must start with '/'")
    # Xray only creates per-user traffic counters for a client assigned to
    # an explicit policy level.  Omitting ``level`` leaves WS clients able to
    # transfer data but makes StatsService return no ``user>>>…>>>traffic``
    # records, so the panel can never determine their live state.
    inbound_clients = [
        {"id": c["id"], "email": c["email"], "flow": "", "level": 0}
        for c in clients
    ]
    return {
        "log": {"loglevel": "none"},
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {"0": {"statsUserUplink": True, "statsUserDownlink": True}},
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [
            build_api_inbound(),
            {
                "tag": "WS",
                "port": port,
                "listen": "127.0.0.1",
                "protocol": "vless",
                "settings": {"clients": inbound_clients, "decryption": "none"},
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
                "streamSettings": {
                    "network": "ws",
                    "security": "none",
                    "wsSettings": {"path": path},
                },
            },
        ],
        "outbounds": [
            {"tag": "DIRECT", "protocol": "freedom"},
            {"tag": "BLOCK", "protocol": "blackhole"},
        ],
        "routing": {
            "rules": [
                # The local dokodemo inbound exposes Xray's gRPC API.  It
                # must be routed back to the built-in ``api`` outbound;
                # without this rule StatsService accepts the query but
                # returns no per-user counters.
                {"type": "field", "inboundTag": ["api"], "outboundTag": "api"},
                {"ip": ["geoip:private"], "outboundTag": "BLOCK"},
                {"domain": ["geosite:private"], "outboundTag": "BLOCK"},
                {"protocol": ["bittorrent"], "outboundTag": "BLOCK"},
            ],
        },
    }


def build_config(
    *,
    source_server_id: int = 0,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
    warp_enabled: bool = False,
    warp_domains: list[str] | None = None,
    service_upstreams: list[dict[str, Any]] | None = None,
    local_ip_region: dict[str, Any] | None = None,
    service_routing_services: set[str] | None = None,
    proxy_protocol_port: int | None = None,
) -> dict[str, Any]:
    """Build the full config.json."""
    vless = build_inbound(
        port=port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )
    outbounds = [
        {"protocol": "freedom", "tag": "direct"},
        {"protocol": "blackhole", "tag": "blocked"},
    ]
    routing_rules = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]
    service_balancers, service_selectors, priority_rules, handled_services = (
        build_service_routing(
            outbounds=outbounds,
            upstreams=service_upstreams or [],
            local_ip_region=local_ip_region,
            enabled_services=service_routing_services,
            source_server_id=source_server_id,
        )
    )
    routing_rules.extend(priority_rules)
    apply_warp_config(
        outbounds,
        routing_rules,
        enabled=warp_enabled,
        domains=warp_domains,
        # The old fixed SOCKS exit is only a last-resort compatibility path.
        # As soon as IP-region can either keep Gemini local or route it to a
        # verified peer, never send it through the hard-coded Netherlands
        # endpoint again.
        gemini_egress_enabled="gemini" not in handled_services,
    )

    # WARP reconciliation prepends its rules. Capability routing must win:
    # otherwise broad legacy Google domains send Gemini back through WARP and
    # defeat the node-local IP-region decision.
    if priority_rules:
        routing_rules[:] = [rule for rule in routing_rules if rule not in priority_rules]
        routing_rules[0:0] = priority_rules
    
    # Catch-all rule: everything that doesn't match previous rules goes direct
    routing_rules.append({
        "type": "field",
        "network": "tcp,udp",
        "outboundTag": "direct"
    })
    
    config: dict[str, Any] = {
        "log": build_log_config(),
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [build_api_inbound(), vless],
        "outbounds": outbounds,
        "routing": {"rules": routing_rules},
    }
    if service_balancers:
        config["routing"]["balancers"] = service_balancers
        config["observatory"] = {
            "subjectSelector": service_selectors,
            "probeUrl": "https://www.gstatic.com/generate_204",
            "probeInterval": "10s",
        }
    return attach_proxy_protocol_inbound(
        config,
        port=proxy_protocol_port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )


def build_balancer_outbound(
    *,
    tag: str,
    upstream_host: str,
    upstream_port: int,
    upstream_sni: str,
    upstream_public_key: str,
    upstream_short_id: str,
    uuid: str,
    flow: str = "xtls-rprx-vision",
    upstream_transport: str = TRANSPORT_TCP,
    upstream_transport_path: str = "",
) -> dict[str, Any]:
    """Build one VLESS+Reality outbound from a balancer node to an upstream
    pool member.

    ``uuid`` is the balancer's auth credential on the upstream — the upstream
    must have this UUID registered as a ``Client`` so xray accepts the
    connection. The panel auto-provisions these service clients when
    ``in_pool`` is toggled on.

    ``upstream_transport`` MUST match the upstream's inbound network or
    xray-core will refuse to handshake. The panel reads it off the
    upstream's Server row. grpc / xhttp upstreams zero out the user's
    flow (vision is incompatible).
    """
    t = (upstream_transport or TRANSPORT_TCP).lower()
    use_flow = t == TRANSPORT_TCP
    stream: dict[str, Any] = {
        "network": t if t in (TRANSPORT_GRPC, TRANSPORT_XHTTP) else TRANSPORT_TCP,
        "security": "reality",
        "realitySettings": {
            "serverName": upstream_sni,
            "fingerprint": "chrome",
            "publicKey": upstream_public_key,
            "shortId": upstream_short_id,
        },
    }
    if t == TRANSPORT_GRPC:
        stream["grpcSettings"] = {
            "serviceName": (upstream_transport_path or "").strip() or "apisub",
        }
    elif t == TRANSPORT_XHTTP:
        stream["xhttpSettings"] = {
            "path": (upstream_transport_path or "").strip() or "/sub",
            "mode": "auto",
        }
    return {
        "tag": tag,
        "protocol": "vless",
        "settings": {
            "vnext": [
                {
                    "address": upstream_host,
                    "port": upstream_port,
                    "users": [
                        {
                            "id": uuid,
                            "flow": flow if use_flow else "",
                            "encryption": "none",
                        }
                    ],
                }
            ]
        },
        "streamSettings": stream,
    }


# Common prefix for balancer-of-pool outbound tags. Used by the xray
# ``routing.balancers[*].selector`` and ``observatory.subjectSelector``
# (both do prefix-match).
BALANCER_OUTBOUND_PREFIX = "pool-"
# Sub-prefix for fallback-tier upstreams. ``pool-fb-<id>`` still starts
# with ``pool-`` so the selector / observatory pick them up alongside
# the primaries; the distinct prefix lets the ``leastLoad`` strategy's
# ``costs`` rule down-rank them so primaries always win when alive.
BALANCER_FALLBACK_PREFIX = "pool-fb-"
BALANCER_TAG = "pool-balancer"

SERVICE_BALANCERS = {
    "youtube": {
        "tag": "service-youtube-balancer",
        "prefix": "svc-youtube-",
        "domains": [
            "domain:youtube.com", "domain:youtu.be", "domain:googlevideo.com",
            "domain:ytimg.com", "domain:youtube-nocookie.com",
        ],
    },
    "gemini": {
        "tag": "service-gemini-balancer",
        "prefix": "svc-gemini-",
        "domains": list(GEMINI_EGRESS_DOMAINS),
    },
    "tiktok": {
        "tag": "service-tiktok-balancer",
        "prefix": "svc-tiktok-",
        "domains": [
            "domain:tiktok.com", "domain:tiktokv.com", "domain:tiktokcdn.com",
            "domain:tiktokcdn-us.com", "domain:musical.ly", "domain:byteoversea.com",
            "domain:ibytedtos.com", "domain:ibyteimg.com",
        ],
    },
    "games": {
        "tag": "service-games-balancer",
        "prefix": "svc-games-",
        # Existing game sockets stay pinned to the chosen outbound. New game
        # connections use the live observatory result with the lowest RTT.
        "strategy": "leastPing",
        # Brawl Stars and the shared Supercell ID/assets flow.  The port rule
        # below is equally important: mobile TUN clients commonly resolve the
        # game host locally and send Xray only the destination IP, leaving no
        # TLS SNI/domain for the server-side sniffer to match.
        "domains": [
            "domain:brawlstarsgame.com", "domain:brawlstars.com",
            "domain:supercell.com", "domain:supercell.net",
            "domain:supercellid.com", "domain:supercellgames.com",
            "domain:scid-cdn.com", "domain:clashofclans.com",
            "domain:clashroyale.com", "domain:clashroyaleapp.com",
        ],
        # Supercell's realtime game protocol uses TCP 9339.  Keep the two
        # adjacent ports because current clients also probe/fall back there.
        "ports": "9338-9340",
    },
}


def _service_routing_rules(
    definition: dict[str, Any],
    *,
    outbound_tag: str | None = None,
    balancer_tag: str | None = None,
) -> list[dict[str, Any]]:
    """Build independent domain and port rules for one service.

    Domain and port in the same Xray field rule are an AND condition.  Games
    need separate rules so raw-IP mobile traffic on port 9339 is still caught.
    """

    target: dict[str, str]
    if balancer_tag:
        target = {"balancerTag": balancer_tag}
    elif outbound_tag:
        target = {"outboundTag": outbound_tag}
    else:
        raise ValueError("service routing rule requires an outbound or balancer")

    rules: list[dict[str, Any]] = []
    domains = list(definition.get("domains") or [])
    if domains:
        rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "domain": domains,
                **target,
            }
        )
    ports = str(definition.get("ports") or "").strip()
    if ports:
        rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "network": "tcp",
                "port": ports,
                **target,
            }
        )
    return rules


def build_service_routing(
    *,
    outbounds: list[dict[str, Any]],
    upstreams: list[dict[str, Any]],
    local_ip_region: dict[str, Any] | None,
    enabled_services: set[str] | None = None,
    source_server_id: int = 0,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]], set[str]]:
    """Attach capability-aware service routing to a regular Xray node.

    A node that already has the requested capability keeps the service local.
    Otherwise it gets a least-load pool containing every verified capable
    peer. This is intentionally generated for each node rather than only for
    the public balancer, so selecting a named country node cannot bypass the
    Gemini/YouTube/TikTok/Supercell-games policy.
    """

    local_caps = _ip_region_routing_caps(local_ip_region)
    balancers: list[dict[str, Any]] = []
    selectors: list[str] = []
    rules: list[dict[str, Any]] = []
    handled: set[str] = set()

    enabled = set(SERVICE_BALANCERS) if enabled_services is None else set(enabled_services)
    for service, definition in SERVICE_BALANCERS.items():
        if service not in enabled:
            continue
        if service in local_caps:
            # Explicit direct beats legacy WARP matchers. The capability was
            # measured on this node's native public egress.
            rules.extend(
                _service_routing_rules(definition, outbound_tag="direct")
            )
            handled.add(service)
            continue

        capable = [
            upstream
            for upstream in upstreams
            if service in _ip_region_routing_caps(upstream.get("ip_region"))
        ]
        if not capable:
            continue

        # Keep every parallel connection of one streaming/app session on the
        # same public egress.  A broad leastLoad selector can choose a
        # different country/IP for each TCP or QUIC connection, which causes
        # intermittent 20-30 second stalls in YouTube and other applications.
        # The source node id spreads ingress nodes deterministically across the
        # verified fleet without changing the egress inside one ingress.
        capable.sort(key=lambda row: int(row.get("id") or 0))
        selected_index = int(source_server_id or 0) % len(capable)
        capable = [capable[selected_index]]

        prefix = str(definition["prefix"])
        for upstream in capable:
            outbounds.append(
                build_balancer_outbound(
                    tag=f"{prefix}{upstream['id']}",
                    upstream_host=upstream["public_host"],
                    upstream_port=int(upstream["port"]),
                    upstream_sni=upstream["sni"],
                    upstream_public_key=upstream["public_key"],
                    upstream_short_id=upstream["short_id"],
                    uuid=upstream["auth_uuid"],
                    flow=upstream.get("flow", "xtls-rprx-vision"),
                    upstream_transport=(upstream.get("transport") or TRANSPORT_TCP),
                    upstream_transport_path=(upstream.get("transport_path") or ""),
                )
            )
        strategy_type = str(definition.get("strategy") or "leastLoad")
        strategy: dict[str, Any] = {"type": strategy_type}
        if strategy_type == "leastLoad":
            strategy["settings"] = {"expected": 1}
        balancers.append(
            {
                "tag": str(definition["tag"]),
                "selector": [prefix],
                # If the selected peer disappears before the next capability
                # rebuild, keep the application reachable through the local
                # node rather than holding connections until timeout.
                "fallbackTag": "direct",
                "strategy": strategy,
            }
        )
        selectors.append(prefix)
        rules.extend(
            _service_routing_rules(
                definition,
                balancer_tag=str(definition["tag"]),
            )
        )
        handled.add(service)

    return balancers, selectors, rules, handled


def _ip_region_service_values(payload: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    custom = (((payload or {}).get("results") or {}).get("custom") or [])
    if not isinstance(custom, list):
        return out
    for row in custom:
        if isinstance(row, dict):
            name = str(row.get("service") or "").strip().casefold()
            if name:
                out[name] = str(row.get("ipv4") or "").strip()
    return out


def _ip_region_routing_caps(payload: dict[str, Any] | None) -> set[str]:
    values = _ip_region_service_values(payload)
    caps: set[str] = set()
    if values.get("youtube", "").upper() == "RU":
        caps.add("youtube")
    if values.get("gemini supported", "").casefold() in {"yes", "true", "supported"}:
        caps.add("gemini")
    tiktok = values.get("tiktok", "").strip()
    invalid = {
        "", "n/a", "na", "no", "denied", "failed", "error", "server error",
        "rate-limit", "rate limit", "timeout", "unknown", "null", "none",
    }
    if tiktok.casefold() not in invalid and tiktok.upper() != "RU":
        caps.add("tiktok")
    # Brawl Stars/Supercell block access when the egress is identified as
    # Russia or Belarus.  Supercell does not disclose its GeoIP supplier, so
    # use two independent game-platform signals from the same IP-region run.
    # A node is admitted only when both are present and non-blocked.
    invalid_countries = {value.upper() for value in invalid}
    steam = values.get("steam", "").strip().upper()
    playstation = values.get("playstation", "").strip().upper()
    if (
        steam not in invalid_countries
        and playstation not in invalid_countries
        and steam not in {"RU", "BY"}
        and playstation not in {"RU", "BY"}
    ):
        caps.add("games")
    return caps

# Cost multiplier applied to ``pool-fb-`` outbounds in the ``leastLoad``
# strategy. ``leastLoad`` ranks candidates by ``RTT * cost``; with a
# cost of 1000 a fallback at 50ms scores 50,000 while a primary at
# 500ms scores 500 — primary wins as long as it's alive. When *all*
# primaries fail their probe, the strategy drops them from the
# candidate set entirely (dead != ranked-last) so the only survivors
# are the fallbacks, and the lowest-RTT fallback wins. End result: a
# single xray balancer that respects tier priority — no need for the
# loopback-balancer hack and without depending on the upstream-only
# ``fallbackBalancerTag`` proposal that was rejected as not_planned
# (XTLS/Xray-core#5188, #5954).
BALANCER_FALLBACK_COST = 1000.0


def build_balancer_config(
    *,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    upstreams: list[dict[str, Any]],
    probe_url: str = "https://www.gstatic.com/generate_204",
    probe_interval: str = "10s",
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
    warp_enabled: bool = False,
    warp_domains: list[str] | None = None,
    service_routing_services: set[str] | None = None,
    proxy_protocol_port: int | None = None,
) -> dict[str, Any]:
    """Build a config for a balancer node.

    Shape:
    * one VLESS+Reality **inbound** (the "public" side users connect to —
      same shape as ``build_config``'s inbound);
    * N VLESS+Reality **outbounds**, one per entry in ``upstreams``,
      tagged either ``pool-<id>`` (primary tier) or ``pool-fb-<id>``
      (fallback tier) — driven by the upstream's ``tier`` field;
    * the ``observatory`` service probes every ``pool-`` outbound on
      ``probe_url`` every ``probe_interval`` to get recent RTTs;
    * a single ``routing.balancers`` entry with ``strategy: leastLoad``
      and a cost penalty on ``pool-fb-`` so primary tier always wins
      while alive — fallbacks only kick in when every primary fails
      its probe. Same end-state as the long-rejected
      ``fallbackBalancerTag`` feature, no loopback hack required;
    * the catch-all routing rule sends every packet from the user
      inbound to that balancer.

    If ``upstreams`` is empty, xray refuses to start with an empty
    balancer selector, so we degrade to a no-pool config that still
    accepts user connections but routes everything through ``freedom``
    (direct egress from the balancer box itself). The admin is expected
    to add pool members and trigger a re-push.

    Each ``upstream`` dict must carry: ``id`` (int, used to build the
    outbound tag), ``public_host``, ``port``, ``sni``, ``public_key``,
    ``short_id``, ``auth_uuid`` (balancer's auth credential on that
    upstream), and optionally ``flow`` (default ``xtls-rprx-vision``)
    and ``tier`` (``"primary"`` / ``"fallback"``; defaults to primary
    so old callers keep working).
    """
    vless = build_inbound(
        port=port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )

    outbounds: list[dict[str, Any]] = []
    enabled_services = (
        set(SERVICE_BALANCERS)
        if service_routing_services is None
        else set(service_routing_services)
    )
    service_counts = {name: 0 for name in SERVICE_BALANCERS}
    for u in upstreams:
        prefix = (
            BALANCER_FALLBACK_PREFIX
            if (u.get("tier") or "").lower() == "fallback"
            else BALANCER_OUTBOUND_PREFIX
        )
        common = {
            "upstream_host": u["public_host"],
            "upstream_port": int(u["port"]),
            "upstream_sni": u["sni"],
            "upstream_public_key": u["public_key"],
            "upstream_short_id": u["short_id"],
            "uuid": u["auth_uuid"],
            "flow": u.get("flow", "xtls-rprx-vision"),
            "upstream_transport": (u.get("transport") or TRANSPORT_TCP),
            "upstream_transport_path": (u.get("transport_path") or ""),
        }
        outbounds.append(
            build_balancer_outbound(
                tag=f"{prefix}{u['id']}",
                **common,
            )
        )
        tier_part = "fb-" if prefix == BALANCER_FALLBACK_PREFIX else "p-"
        service_caps = (
            set()
            if u.get("service_routing_exit_excluded")
            else _ip_region_routing_caps(u.get("ip_region"))
        )
        for service in service_caps & enabled_services:
            service_prefix = str(SERVICE_BALANCERS[service]["prefix"])
            outbounds.append(
                build_balancer_outbound(
                    tag=f"{service_prefix}{tier_part}{u['id']}",
                    **common,
                )
            )
            service_counts[service] += 1
    # Standard helper outbounds — kept even when a balancer is in use so
    # xray has something to fall back on for the local probe traffic.
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "blocked"})

    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]
    balancers: list[dict[str, Any]] = []
    observatory: dict[str, Any] | None = None

    if outbounds and any(o.get("tag", "").startswith(BALANCER_OUTBOUND_PREFIX)
                          for o in outbounds):
        balancers.append(
            {
                "tag": BALANCER_TAG,
                "selector": [BALANCER_OUTBOUND_PREFIX],
                "strategy": {
                    "type": "leastLoad",
                    "settings": {
                        # Pick exactly one outbound per request; without
                        # this xray's leastLoad falls back to "all
                        # qualified" and only sorts them, which is fine
                        # too but ``expected: 1`` makes the intent
                        # explicit.
                        "expected": 1,
                        # Cost multiplier on RTT. xray's ``WeightManager``
                        # uses ``strings.Contains(tag, match)`` so the
                        # bare prefix ``pool-fb-`` only catches fallback
                        # rows (``pool-3`` doesn't contain ``pool-fb-``).
                        "costs": [
                            {
                                "match": BALANCER_FALLBACK_PREFIX,
                                "value": BALANCER_FALLBACK_COST,
                            }
                        ],
                    },
                },
            }
        )
        service_rules: list[dict[str, Any]] = []
        for service, definition in SERVICE_BALANCERS.items():
            if not service_counts[service]:
                continue
            service_prefix = str(definition["prefix"])
            strategy_type = str(definition.get("strategy") or "leastLoad")
            strategy: dict[str, Any] = {"type": strategy_type}
            if strategy_type == "leastLoad":
                strategy["settings"] = {
                    "expected": 1,
                    "costs": [
                        {
                            "match": f"{service_prefix}fb-",
                            "value": BALANCER_FALLBACK_COST,
                        }
                    ],
                }
            balancers.append(
                {
                    "tag": str(definition["tag"]),
                    "selector": [service_prefix],
                    "strategy": strategy,
                }
            )
            service_rules.extend(
                _service_routing_rules(
                    definition,
                    balancer_tag=str(definition["tag"]),
                )
            )
        routing_rules.extend(service_rules)
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "balancerTag": BALANCER_TAG,
            }
        )
        observatory = {
            "subjectSelector": [BALANCER_OUTBOUND_PREFIX]
            + [
                str(definition["prefix"])
                for service, definition in SERVICE_BALANCERS.items()
                if service_counts[service]
            ],
            "probeUrl": probe_url,
            "probeInterval": probe_interval,
        }
    else:
        # No pool members — send user traffic out direct so the balancer
        # is at least reachable / testable. Admin will notice zero-pool
        # from the UI badge and add members.
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "outboundTag": "direct",
            }
        )

    apply_warp_config(
        outbounds,
        routing_rules,
        enabled=warp_enabled,
        domains=warp_domains,
        gemini_egress_enabled=not bool(service_counts["gemini"]),
    )

    # ``apply_warp_config`` prepends its rules. Service-specific routing on a
    # balancer must win even when the node's legacy WARP list contains broad
    # Google/TikTok matchers, so move the dynamic service rules back to the
    # very front while preserving their relative order.
    service_tags = {str(item["tag"]) for item in SERVICE_BALANCERS.values()}
    dynamic_rules = [
        rule for rule in routing_rules if str(rule.get("balancerTag") or "") in service_tags
    ]
    if dynamic_rules:
        routing_rules[:] = [rule for rule in routing_rules if rule not in dynamic_rules]
        routing_rules[0:0] = dynamic_rules

    config: dict[str, Any] = {
        "log": build_log_config(),
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [build_api_inbound(), vless],
        "outbounds": outbounds,
        "routing": {
            "balancers": balancers,
            "rules": routing_rules,
        },
    }
    if observatory is not None:
        config["observatory"] = observatory
    return attach_proxy_protocol_inbound(
        config,
        port=proxy_protocol_port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )


# Outbound tag used on a whitelist-front node to dial its single
# foreign upstream. Routing on the front sends every byte from the
# user-facing inbound to this tag.
BYPASS_OUTBOUND_TAG = "bypass-upstream"


# Domains used by Xray-based clients for their built-in latency check
# (``www.gstatic.com/generate_204``, ``cp.cloudflare.com/generate_204``,
# ``captive.apple.com``, etc.). On a whitelist-front node we short-
# circuit these to the front's own ``direct`` outbound so the user sees
# a client→RU-front RTT in the client UI instead of the full
# client→RU→LT RTT of a real tunneled request. Ordinary browser traffic
# to these CDNs will also egress from the front directly — that's
# acceptable since they're pure CDNs with no personal data.
PING_TEST_DOMAINS = [
    "domain:gstatic.com",
    "full:cp.cloudflare.com",
    "full:captive.apple.com",
    "full:connectivitycheck.gstatic.com",
]


def build_whitelist_front_config(
    *,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    upstream: dict[str, Any] | None,
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
    warp_enabled: bool = False,
    warp_domains: list[str] | None = None,
    proxy_protocol_port: int | None = None,
) -> dict[str, Any]:
    """Build a config for a ``whitelist-front`` node.

    Shape:
    * one VLESS+Reality **inbound** identical to a standalone node — this
      is what end users connect to with their ``vless://`` link;
    * one VLESS+Reality **outbound** dialing ``upstream`` (a foreign
      server's public_host:port + Reality keys + the panel-managed
      ``__bypass__-<id>`` auth UUID);
    * a single routing rule: anything from the user inbound goes to that
      outbound.

    When ``upstream`` is ``None`` (admin hasn't picked one yet, or the
    upstream Server row was deleted), the node degrades to a no-op
    config that still accepts user connections but routes everything
    through ``freedom`` direct egress on the front itself. The admin
    will see ``upstream: —`` in the UI and link the front to a foreign
    backend.

    ``upstream`` dict shape: ``public_host``, ``port``, ``sni``,
    ``public_key``, ``short_id``, ``auth_uuid`` (the front's auth
    credential on the upstream), optionally ``flow`` (default
    ``xtls-rprx-vision``).
    """
    vless = build_inbound(
        port=port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )

    outbounds: list[dict[str, Any]] = []
    routing_rules: list[dict[str, Any]] = [
        {
            "type": "field",
            "inboundTag": ["api"],
            "outboundTag": "api",
        }
    ]
    if upstream is not None:
        outbounds.append(
            build_balancer_outbound(
                tag=BYPASS_OUTBOUND_TAG,
                upstream_host=upstream["public_host"],
                upstream_port=int(upstream["port"]),
                upstream_sni=upstream["sni"],
                upstream_public_key=upstream["public_key"],
                upstream_short_id=upstream["short_id"],
                uuid=upstream["auth_uuid"],
                flow=upstream.get("flow", "xtls-rprx-vision"),
                upstream_transport=(upstream.get("transport") or TRANSPORT_TCP),
                upstream_transport_path=(upstream.get("transport_path") or ""),
            )
        )
        # Latency-check fast path: client ping probes to well-known test
        # URLs egress from the front itself, not through the foreign
        # upstream. Must be listed before the catch-all below so xray's
        # first-match routing picks it up.
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "domain": PING_TEST_DOMAINS,
                "outboundTag": "direct",
            }
        )
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "outboundTag": BYPASS_OUTBOUND_TAG,
            }
        )
    else:
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "outboundTag": "direct",
            }
        )
    outbounds.append({"protocol": "freedom", "tag": "direct"})
    outbounds.append({"protocol": "blackhole", "tag": "blocked"})

    apply_warp_config(
        outbounds,
        routing_rules,
        enabled=warp_enabled,
        domains=warp_domains,
    )

    config = {
        "log": build_log_config(),
        "api": {
            "tag": "api",
            "services": ["HandlerService", "LoggerService", "StatsService"],
        },
        "stats": {},
        "policy": {
            "levels": {
                "0": {
                    "statsUserUplink": True,
                    "statsUserDownlink": True,
                }
            },
            "system": {
                "statsInboundUplink": True,
                "statsInboundDownlink": True,
                "statsOutboundUplink": True,
                "statsOutboundDownlink": True,
            },
        },
        "inbounds": [build_api_inbound(), vless],
        "outbounds": outbounds,
        "routing": {"rules": routing_rules},
    }
    return attach_proxy_protocol_inbound(
        config,
        port=proxy_protocol_port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
        transport=transport,
        transport_path=transport_path,
    )


def build_vless_link(
    *,
    uuid: str,
    host: str,
    port: int,
    public_key: str,
    sni: str,
    short_id: str,
    label: str,
    flow: str = "xtls-rprx-vision",
    transport: str = TRANSPORT_TCP,
    transport_path: str = "",
) -> str:
    """Build a ``vless://`` connection link.

    The transport-specific tail mirrors what every modern vless client
    expects (Hiddify / v2rayNG / Karing / Happ / sing-box):

    * tcp   — ``type=tcp&flow=<flow>``
    * grpc  — ``type=grpc&serviceName=<name>&mode=gun`` (flow stripped:
              xray-core rejects vision on grpc)
    * xhttp — ``type=xhttp&path=<path>&host=<sni>&mode=auto`` (flow
              stripped)
    """
    from urllib.parse import quote

    frag = quote(label, safe="")
    t = (transport or TRANSPORT_TCP).lower()
    pbk_part = (
        f"security=reality&encryption=none&pbk={public_key}"
        f"&fp=chrome&sni={sni}&sid={short_id}"
    )
    if t == TRANSPORT_GRPC:
        service = quote((transport_path or "").strip() or "apisub", safe="")
        return (
            f"vless://{uuid}@{host}:{port}"
            f"?{pbk_part}&type=grpc&serviceName={service}&mode=gun"
            f"#{frag}"
        )
    if t == TRANSPORT_XHTTP:
        path = quote((transport_path or "").strip() or "/sub", safe="/")
        host_q = quote(sni, safe="")
        return (
            f"vless://{uuid}@{host}:{port}"
            f"?{pbk_part}&type=xhttp&path={path}&host={host_q}&mode=auto"
            f"#{frag}"
        )
    # tcp (default): keep the historical link shape byte-for-byte so
    # links generated before the multi-transport feature shipped still
    # parse identically after an upgrade.
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?security=reality&encryption=none&pbk={public_key}"
        f"&fp=chrome&type=tcp&flow={flow}&sni={sni}&sid={short_id}"
        f"#{frag}"
    )


def build_vless_ws_tls_link(
    *,
    uuid: str,
    host: str,
    port: int,
    path: str,
    sni: str,
    label: str,
) -> str:
    """Build a VLESS-over-WebSocket link for an externally terminated TLS vhost.

    The node owner owns the domain, certificate and reverse proxy.  Xray sees
    only the loopback WS inbound, so this renderer deliberately never creates
    or alters TLS/SNI infrastructure on the node.  ``sni`` is optional: an
    empty value omits the URI parameter and leaves the client to use the dial
    host for TLS SNI.
    """
    from urllib.parse import quote

    ws_path = quote((path or "/").strip() or "/", safe="/")
    host_q = quote(host.strip(), safe="")
    params = [
        "encryption=none",
        "type=ws",
        f"path={ws_path}",
        f"host={host_q}",
        "security=tls",
        "fp=firefox",
        "alpn=http%2F1.1",
    ]
    if (sni or "").strip():
        params.append(f"sni={quote(sni.strip(), safe='')}")
    return f"vless://{uuid}@{host}:{port}?{'&'.join(params)}#{quote(label, safe='')}"

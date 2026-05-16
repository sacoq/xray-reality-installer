"""Build xray-core config.json from our data model.

Shared between panel (generates config to push) and agent (writes it).
"""
from __future__ import annotations

from typing import Any


# Stats / API port used by the local xray instance (localhost-only).
XRAY_API_PORT = 10085


def build_inbound(
    *,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    tag: str = "vless-reality",
) -> dict[str, Any]:
    """Build the VLESS+Reality inbound.

    ``server_names`` is the full list of SNIs the inbound accepts; the
    first one is treated as the "primary" / default and is what the
    panel uses when a client doesn't pin a specific SNI of its own.
    All other entries let admins serve different keys with different
    SNIs from the same inbound (helpful when a single SNI starts
    getting DPI-flagged on a mobile operator).

    Each client dict must have: id (uuid), email, flow (default xtls-rprx-vision).
    """
    if not server_names:
        raise ValueError("build_inbound requires at least one serverName")

    inbound_clients: list[dict[str, Any]] = []
    for c in clients:
        entry = {
            "id": c["id"],
            "flow": c.get("flow", "xtls-rprx-vision"),
            "email": c["email"],
        }
        inbound_clients.append(entry)

    return {
        "tag": tag,
        "listen": "0.0.0.0",
        "port": port,
        "protocol": "vless",
        "settings": {
            "clients": inbound_clients,
            "decryption": "none",
        },
        "streamSettings": {
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
            "security": "reality",
            "realitySettings": {
                "show": False,
                "dest": dest,
                "xver": 0,
                "serverNames": list(server_names),
                "privateKey": private_key,
                "shortIds": short_ids,
            },
        },
        "sniffing": {
            "enabled": True,
            "destOverride": ["http", "tls", "quic"],
        },
    }


def build_api_inbound() -> dict[str, Any]:
    """Expose xray's gRPC API on localhost for stats / runtime control."""
    return {
        "tag": "api",
        "listen": "127.0.0.1",
        "port": XRAY_API_PORT,
        "protocol": "dokodemo-door",
        "settings": {"address": "127.0.0.1"},
    }


def build_config(
    *,
    port: int,
    server_names: list[str],
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the full config.json."""
    vless = build_inbound(
        port=port,
        server_names=server_names,
        dest=dest,
        private_key=private_key,
        short_ids=short_ids,
        clients=clients,
    )
    return {
        "log": {"loglevel": "warning"},
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
        "outbounds": [
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "blocked"},
        ],
        "routing": {
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["api"],
                    "outboundTag": "api",
                }
            ]
        },
    }


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
) -> dict[str, Any]:
    """Build one VLESS+Reality outbound from a balancer node to an upstream
    pool member.

    ``uuid`` is the balancer's auth credential on the upstream — the upstream
    must have this UUID registered as a ``Client`` so xray accepts the
    connection. The panel auto-provisions these service clients when
    ``in_pool`` is toggled on.
    """
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
                            "flow": flow,
                            "encryption": "none",
                        }
                    ],
                }
            ]
        },
        "streamSettings": {
            "network": "tcp",
            "security": "reality",
            "realitySettings": {
                "serverName": upstream_sni,
                "fingerprint": "chrome",
                "publicKey": upstream_public_key,
                "shortId": upstream_short_id,
            },
        },
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
    )

    outbounds: list[dict[str, Any]] = []
    for u in upstreams:
        prefix = (
            BALANCER_FALLBACK_PREFIX
            if (u.get("tier") or "").lower() == "fallback"
            else BALANCER_OUTBOUND_PREFIX
        )
        outbounds.append(
            build_balancer_outbound(
                tag=f"{prefix}{u['id']}",
                upstream_host=u["public_host"],
                upstream_port=int(u["port"]),
                upstream_sni=u["sni"],
                upstream_public_key=u["public_key"],
                upstream_short_id=u["short_id"],
                uuid=u["auth_uuid"],
                flow=u.get("flow", "xtls-rprx-vision"),
            )
        )
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
        routing_rules.append(
            {
                "type": "field",
                "inboundTag": ["vless-reality"],
                "balancerTag": BALANCER_TAG,
            }
        )
        observatory = {
            "subjectSelector": [BALANCER_OUTBOUND_PREFIX],
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

    config: dict[str, Any] = {
        "log": {"loglevel": "warning"},
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
    return config


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

    return {
        "log": {"loglevel": "warning"},
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
) -> str:
    """Build a ``vless://`` connection link."""
    from urllib.parse import quote

    frag = quote(label, safe="")
    return (
        f"vless://{uuid}@{host}:{port}"
        f"?security=reality&encryption=none&pbk={public_key}"
        f"&fp=chrome&type=tcp&flow={flow}&sni={sni}&sid={short_id}"
        f"#{frag}"
    )

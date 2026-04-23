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
    sni: str,
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
    tag: str = "vless-reality",
) -> dict[str, Any]:
    """Build the VLESS+Reality inbound.

    Each client dict must have: id (uuid), email, flow (default xtls-rprx-vision).
    """
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
                "serverNames": [sni],
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
    sni: str,
    dest: str,
    private_key: str,
    short_ids: list[str],
    clients: list[dict[str, Any]],
) -> dict[str, Any]:
    """Build the full config.json."""
    vless = build_inbound(
        port=port,
        sni=sni,
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

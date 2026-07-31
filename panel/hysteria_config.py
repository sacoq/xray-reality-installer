"""Hysteria 2 server configuration and subscription-link helpers.

Hysteria is a separate QUIC/UDP service; it is not an Xray inbound.  Keeping
its renderer in a dedicated module makes that boundary explicit and prevents
the existing VLESS+Reality builders from accumulating protocol-specific
branches.
"""
from __future__ import annotations

import copy
import json
import re
from typing import Any, Iterable
from urllib.parse import quote, urlencode


PROTOCOL_VLESS = "vless-reality"
PROTOCOL_HYSTERIA2 = "hysteria2"
PROTOCOLS = (PROTOCOL_VLESS, PROTOCOL_HYSTERIA2)
HYSTERIA_AUTH_USERPASS = "userpass"
HYSTERIA_AUTH_PASSWORD = "password"
HYSTERIA_AUTH_MODES = (HYSTERIA_AUTH_USERPASS, HYSTERIA_AUTH_PASSWORD)

HYSTERIA_TLS_ACME = "acme"
HYSTERIA_TLS_FILES = "files"
HYSTERIA_TLS_MODES = (HYSTERIA_TLS_ACME, HYSTERIA_TLS_FILES)

HYSTERIA_OBFS_NONE = ""
HYSTERIA_OBFS_SALAMANDER = "salamander"
HYSTERIA_OBFS_GECKO = "gecko"
HYSTERIA_OBFS_TYPES = (
    HYSTERIA_OBFS_NONE,
    HYSTERIA_OBFS_SALAMANDER,
    HYSTERIA_OBFS_GECKO,
)

HYSTERIA_CONGESTION_BBR = "bbr"
HYSTERIA_CONGESTION_RENO = "reno"
HYSTERIA_CONGESTIONS = (HYSTERIA_CONGESTION_BBR, HYSTERIA_CONGESTION_RENO)
HYSTERIA_BBR_PROFILES = ("standard", "conservative", "aggressive")

_LISTEN_RE = re.compile(r"^\d{1,5}(?:-\d{1,5})?$")

# Advanced JSON is intentionally powerful but cannot replace the fields the
# panel needs for lifecycle, authentication, TLS and traffic accounting.
_ADVANCED_ALLOWED = frozenset(
    {
        "acl",
        "ech",
        "quic",
        "realm",
        "resolver",
        "outbounds",
        "sniff",
        "speedTest",
    }
)


def normalise_protocol(value: str | None) -> str:
    protocol = (value or "").strip().lower() or PROTOCOL_VLESS
    aliases = {
        "vless": PROTOCOL_VLESS,
        "reality": PROTOCOL_VLESS,
        "hy2": PROTOCOL_HYSTERIA2,
        "hysteria": PROTOCOL_HYSTERIA2,
    }
    protocol = aliases.get(protocol, protocol)
    if protocol not in PROTOCOLS:
        raise ValueError(
            f"unknown protocol: {value!r} (expected {', '.join(PROTOCOLS)})"
        )
    return protocol


def is_hysteria2(value: Any) -> bool:
    raw = getattr(value, "protocol", value)
    return normalise_protocol(str(raw or "")) == PROTOCOL_HYSTERIA2


def normalise_auth_mode(value: str | None) -> str:
    mode = (value or "").strip().lower() or HYSTERIA_AUTH_USERPASS
    aliases = {"user-pass": HYSTERIA_AUTH_USERPASS, "shared": HYSTERIA_AUTH_PASSWORD}
    mode = aliases.get(mode, mode)
    if mode not in HYSTERIA_AUTH_MODES:
        raise ValueError(
            f"Hysteria auth mode must be '{HYSTERIA_AUTH_USERPASS}' or "
            f"'{HYSTERIA_AUTH_PASSWORD}'"
        )
    return mode


def normalise_listen(value: str | None, *, fallback_port: int) -> str:
    """Return a Hysteria listen/URI port expression.

    Hysteria supports a single port or one Linux port-hopping range.  Keeping
    this validator narrow avoids accidentally accepting shell fragments or an
    address that would make the service bind somewhere the UI did not show.
    """
    raw = (value or "").strip() or str(int(fallback_port))
    if not _LISTEN_RE.fullmatch(raw):
        raise ValueError("Hysteria listen must be a port or range, e.g. 443 or 20000-50000")
    if "-" in raw:
        start_raw, end_raw = raw.split("-", 1)
        start, end = int(start_raw), int(end_raw)
        if not (1 <= start <= end <= 65535):
            raise ValueError("Hysteria port range must be inside 1..65535")
    elif not 1 <= int(raw) <= 65535:
        raise ValueError("Hysteria port must be inside 1..65535")
    return raw


def _normalise_tls_mode(value: str | None) -> str:
    mode = (value or "").strip().lower() or HYSTERIA_TLS_ACME
    if mode not in HYSTERIA_TLS_MODES:
        raise ValueError("Hysteria TLS mode must be 'acme' or 'files'")
    return mode


def _normalise_obfs(value: str | None) -> str:
    obfs = (value or "").strip().lower()
    if obfs not in HYSTERIA_OBFS_TYPES:
        raise ValueError("Hysteria obfs must be empty, 'salamander' or 'gecko'")
    return obfs


def _normalise_congestion(value: str | None) -> str:
    congestion = (value or "").strip().lower() or HYSTERIA_CONGESTION_BBR
    if congestion not in HYSTERIA_CONGESTIONS:
        raise ValueError("Hysteria congestion must be 'bbr' or 'reno'")
    return congestion


def _normalise_bbr_profile(value: str | None) -> str:
    profile = (value or "").strip().lower() or "standard"
    if profile not in HYSTERIA_BBR_PROFILES:
        raise ValueError(
            "Hysteria BBR profile must be standard, conservative or aggressive"
        )
    return profile


def parse_advanced_json(value: str | None) -> dict[str, Any]:
    raw = (value or "").strip()
    if not raw:
        return {}
    try:
        payload = json.loads(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Hysteria advanced JSON is invalid: {exc}") from exc
    if not isinstance(payload, dict):
        raise ValueError("Hysteria advanced JSON must be an object")
    unknown = sorted(set(payload) - _ADVANCED_ALLOWED)
    if unknown:
        raise ValueError(
            "Hysteria advanced JSON contains protected/unknown keys: "
            + ", ".join(unknown)
        )
    return payload


def build_hysteria_config(
    *,
    port: int,
    listen: str = "",
    sni: str,
    tls_mode: str = HYSTERIA_TLS_ACME,
    acme_email: str = "",
    cert_path: str = "",
    key_path: str = "",
    clients: Iterable[dict[str, Any]],
    auth_mode: str = HYSTERIA_AUTH_USERPASS,
    auth_password: str = "",
    stats_secret: str,
    stats_port: int = 9999,
    obfs_type: str = "",
    obfs_password: str = "",
    up_mbps: int = 0,
    down_mbps: int = 0,
    ignore_client_bandwidth: bool = False,
    congestion: str = HYSTERIA_CONGESTION_BBR,
    bbr_profile: str = "standard",
    disable_udp: bool = False,
    udp_idle_timeout_seconds: int = 60,
    masquerade_url: str = "https://news.ycombinator.com/",
    advanced_json: str = "",
) -> dict[str, Any]:
    """Build a complete Hysteria 2 server config managed by the panel."""
    listen_value = normalise_listen(listen, fallback_port=port)
    tls = _normalise_tls_mode(tls_mode)
    auth_mode = normalise_auth_mode(auth_mode)
    obfs = _normalise_obfs(obfs_type)
    congestion_type = _normalise_congestion(congestion)
    profile = _normalise_bbr_profile(bbr_profile)
    domain = (sni or "").strip().lower()
    if not domain:
        raise ValueError("Hysteria TLS domain/SNI is required")
    if not stats_secret:
        raise ValueError("Hysteria traffic stats secret is required")
    if not 1 <= int(stats_port) <= 65535:
        raise ValueError("Hysteria traffic stats port must be inside 1..65535")
    if int(udp_idle_timeout_seconds) < 5 or int(udp_idle_timeout_seconds) > 3600:
        raise ValueError("Hysteria UDP idle timeout must be between 5 and 3600 seconds")

    users: dict[str, str] = {}
    for client in clients:
        username = str(client.get("email") or "").strip()
        password = str(client.get("password") or client.get("id") or "").strip()
        if username and password:
            users[username] = password

    if auth_mode == HYSTERIA_AUTH_PASSWORD:
        shared_password = (auth_password or "").strip()
        if not shared_password:
            raise ValueError("Hysteria shared password is required for password auth")
        auth_config: dict[str, Any] = {
            "type": HYSTERIA_AUTH_PASSWORD,
            "password": shared_password,
        }
    else:
        auth_config = {"type": HYSTERIA_AUTH_USERPASS, "userpass": users}

    config: dict[str, Any] = {
        "listen": f":{listen_value}",
        "auth": auth_config,
        "trafficStats": {
            "listen": f"127.0.0.1:{int(stats_port)}",
            "secret": stats_secret,
        },
        "congestion": {"type": congestion_type},
        "ignoreClientBandwidth": bool(ignore_client_bandwidth),
        "disableUDP": bool(disable_udp),
        "udpIdleTimeout": f"{int(udp_idle_timeout_seconds)}s",
    }
    if congestion_type == HYSTERIA_CONGESTION_BBR:
        config["congestion"]["bbrProfile"] = profile

    if tls == HYSTERIA_TLS_ACME:
        if not (acme_email or "").strip():
            raise ValueError("Hysteria ACME email is required")
        config["acme"] = {
            "domains": [domain],
            "email": acme_email.strip(),
            "ca": "letsencrypt",
            "type": "http",
        }
    else:
        if not (cert_path or "").strip() or not (key_path or "").strip():
            raise ValueError("Hysteria certificate and key paths are required")
        config["tls"] = {
            "cert": cert_path.strip(),
            "key": key_path.strip(),
            "sniGuard": "strict",
        }

    if obfs:
        if not (obfs_password or "").strip():
            raise ValueError(f"Hysteria {obfs} obfuscation password is required")
        config["obfs"] = {
            "type": obfs,
            obfs: {"password": obfs_password.strip()},
        }

    bandwidth: dict[str, str] = {}
    if int(up_mbps or 0) > 0:
        bandwidth["up"] = f"{int(up_mbps)} mbps"
    if int(down_mbps or 0) > 0:
        bandwidth["down"] = f"{int(down_mbps)} mbps"
    if bandwidth:
        config["bandwidth"] = bandwidth

    if (masquerade_url or "").strip():
        config["masquerade"] = {
            "type": "proxy",
            "proxy": {
                "url": masquerade_url.strip(),
                "rewriteHost": True,
            },
        }

    for key, value in parse_advanced_json(advanced_json).items():
        config[key] = copy.deepcopy(value)
    return config


def build_hysteria_link(
    *,
    username: str = "",
    password: str,
    host: str,
    port: int,
    listen: str = "",
    sni: str,
    label: str,
    obfs_type: str = "",
    obfs_password: str = "",
    insecure: bool = False,
    auth_mode: str = HYSTERIA_AUTH_USERPASS,
) -> str:
    """Build the official ``hysteria2://`` URI form."""
    listen_value = normalise_listen(listen, fallback_port=port)
    auth_mode = normalise_auth_mode(auth_mode)
    hostname = (host or "").strip()
    if ":" in hostname and not hostname.startswith("["):
        hostname = f"[{hostname}]"
    if auth_mode == HYSTERIA_AUTH_PASSWORD:
        if not (password or "").strip():
            raise ValueError("Hysteria shared password is required for password auth")
        auth = quote(password, safe="")
    else:
        if not (username or "").strip():
            raise ValueError("Hysteria username is required for userpass auth")
        auth = f"{quote(username, safe='')}:{quote(password, safe='')}"
    # Keep the order used by hysteria2-autosetup in shared-password mode:
    # obfs parameters first, then SNI. Preserve the legacy ``insecure=0``
    # marker for userpass links so existing clients keep receiving the same
    # explicit verification setting.
    params: list[tuple[str, str]] = []
    obfs = _normalise_obfs(obfs_type)
    if obfs:
        params.append(("obfs", obfs))
        params.append(("obfs-password", obfs_password or ""))
    params.append(("sni", (sni or "").strip()))
    if insecure or auth_mode == HYSTERIA_AUTH_USERPASS:
        params.append(("insecure", "1" if insecure else "0"))
    query = urlencode(params)
    return (
        f"hysteria2://{auth}@{hostname}:{listen_value}/?{query}"
        f"#{quote(label, safe='')}"
    )


__all__ = [
    "HYSTERIA_BBR_PROFILES",
    "HYSTERIA_CONGESTIONS",
    "HYSTERIA_AUTH_MODES",
    "HYSTERIA_AUTH_PASSWORD",
    "HYSTERIA_AUTH_USERPASS",
    "HYSTERIA_OBFS_TYPES",
    "HYSTERIA_TLS_MODES",
    "PROTOCOL_HYSTERIA2",
    "PROTOCOL_VLESS",
    "build_hysteria_config",
    "build_hysteria_link",
    "is_hysteria2",
    "normalise_listen",
    "normalise_auth_mode",
    "normalise_protocol",
    "parse_advanced_json",
]

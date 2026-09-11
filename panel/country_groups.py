"""Country-aware node grouping and routing weights.

One public country gateway keeps the client subscription compact while its
numbered peers stay as private balancer upstreams.  The helpers are deliberately
side-effect free except for ``reconcile_country_group`` so they can be tested
without contacting a node.
"""
from __future__ import annotations

import ipaddress
import math
import re
import socket
from datetime import datetime, timedelta

import httpx
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .models import Server, ServerMetricDaily, server_tags


COUNTRY_NAMES_RU = {
    "AL": "Албания", "AT": "Австрия", "BE": "Бельгия", "BG": "Болгария",
    "BY": "Беларусь", "CA": "Канада", "CH": "Швейцария", "CN": "Китай",
    "CZ": "Чехия", "DE": "Германия", "DK": "Дания", "EE": "Эстония",
    "ES": "Испания", "FI": "Финляндия", "FR": "Франция", "GB": "Англия",
    "GE": "Грузия", "GR": "Греция", "HK": "Гонконг", "HR": "Хорватия",
    "HU": "Венгрия", "IE": "Ирландия", "IL": "Израиль", "IS": "Исландия",
    "IT": "Италия", "JP": "Япония", "KZ": "Казахстан", "LT": "Литва",
    "LU": "Люксембург", "LV": "Латвия", "MD": "Молдова", "ME": "Черногория",
    "NL": "Нидерланды", "NO": "Норвегия", "PL": "Польша", "PT": "Португалия",
    "RO": "Румыния", "RS": "Сербия", "RU": "Россия", "SE": "Швеция",
    "SG": "Сингапур", "SK": "Словакия", "TR": "Турция", "UA": "Украина",
    "US": "США",
}


def flag_emoji(code: str) -> str:
    code = (code or "").strip().upper()
    if len(code) != 2 or not code.isalpha():
        return "🌐"
    return "".join(chr(127397 + ord(ch)) for ch in code)


def normalise_country(code: str, name: str = "") -> tuple[str, str]:
    code = (code or "").strip().upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        raise ValueError("country_code must be a two-letter ISO code")
    value = (name or "").strip() or COUNTRY_NAMES_RU.get(code, code)
    return code, value[:96]


def country_options() -> list[dict[str, str]]:
    return [
        {"code": code, "name": name, "flag": flag_emoji(code)}
        for code, name in sorted(COUNTRY_NAMES_RU.items(), key=lambda item: item[1])
    ]


def match_country(query: str) -> tuple[str, str]:
    """Resolve a manual ISO code or an unambiguous Russian-name prefix."""
    value = (query or "").strip()
    if not value:
        raise ValueError("country is empty")
    upper = value.upper()
    if upper in COUNTRY_NAMES_RU:
        return normalise_country(upper)
    folded = value.casefold()
    exact = [(code, name) for code, name in COUNTRY_NAMES_RU.items()
             if name.casefold() == folded]
    if exact:
        return exact[0]
    matches = [(code, name) for code, name in COUNTRY_NAMES_RU.items()
               if name.casefold().startswith(folded)]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise ValueError(f"unknown country: {value}")
    raise ValueError(f"country name is ambiguous: {value}")


def _public_ip(host: str) -> str:
    raw = (host or "").strip().strip("[]")
    if not raw:
        raise ValueError("IP/host is required")
    try:
        values = [str(ipaddress.ip_address(raw))]
    except ValueError:
        values = [row[4][0].split("%", 1)[0] for row in socket.getaddrinfo(
            raw, None, type=socket.SOCK_STREAM
        )]
    for value in values:
        ip = ipaddress.ip_address(value)
        if ip.is_global:
            return str(ip)
    raise ValueError("host must resolve to a public IP address")


def detect_country(host: str, *, timeout: float = 8.0) -> dict:
    """Resolve a public node and obtain its Russian country name."""
    ip = _public_ip(host)
    try:
        registration = registration_countries(ip, timeout=timeout)
    except Exception:
        # Registration is informational only. Admission is based on the
        # node-local TikTok result and Latency Lab wire verdict.
        registration = []
    response = httpx.get(
        f"https://ipwho.is/{ip}",
        params={"lang": "ru", "fields": "success,country,country_code,flag.emoji"},
        timeout=timeout,
        follow_redirects=True,
        headers={"User-Agent": "xnPanel-country-detect/1.0"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or payload.get("success") is not True:
        raise ValueError(str(payload.get("message") or "country lookup failed"))
    code, name = normalise_country(
        str(payload.get("country_code") or ""), str(payload.get("country") or "")
    )
    return {"ip": ip, "country_code": code, "country_name": name,
            "registration_countries": registration,
            "flag": str((payload.get("flag") or {}).get("emoji") or flag_emoji(code))}


def registration_countries(ip_or_host: str, *, timeout: float = 8.0) -> list[str]:
    """Return country codes from the authoritative RIR RDAP record."""
    ip = _public_ip(ip_or_host)
    response = httpx.get(
        f"https://rdap.org/ip/{ip}", timeout=timeout, follow_redirects=True,
        headers={"User-Agent": "xnPanel-rdap-check/1.0"},
    )
    response.raise_for_status()
    payload = response.json()
    countries: list[str] = []
    for item in _walk_values(payload):
        if isinstance(item, dict):
            value = str(item.get("country") or "").strip().upper()
            if re.fullmatch(r"[A-Z]{2}", value) and value not in countries:
                countries.append(value)
    return countries


def _walk_values(value):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk_values(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk_values(nested)


def infer_country_code(label: str) -> str:
    folded = re.sub(r"[^0-9A-Za-zА-Яа-яЁё]+", " ", label or "").casefold()
    for code, name in COUNTRY_NAMES_RU.items():
        if name.casefold() in folded:
            return code
    return ""


def _base_label(server: Server) -> str:
    value = (getattr(server, "display_name", "") or server.name or "").strip()
    value = re.sub(r"^[\U0001F1E6-\U0001F1FF]{2}\s*", "", value).strip()
    return re.sub(r"\s+\d+\s*$", "", value).strip()


def allocate_node_identity(db: Session, code: str, country_name: str) -> dict:
    """Return a collision-free technical name and numbered admin label."""
    code, country_name = normalise_country(code, country_name)
    related = [s for s in db.scalars(select(Server).order_by(Server.id)).all()
               if (getattr(s, "country_code", "") or infer_country_code(
                   (getattr(s, "display_name", "") or "") + " " + (s.name or "")
               )).upper() == code]
    ordinal = len(related) + 1
    stem = code.lower()
    technical = stem if ordinal == 1 else f"{stem}-{ordinal}"
    existing = {s.name for s in db.scalars(select(Server)).all()}
    while technical in existing:
        ordinal += 1
        technical = f"{stem}-{ordinal}"
    display = f"{flag_emoji(code)} {country_name}"
    if ordinal > 1:
        display += f" {ordinal}"
    return {"name": technical, "display_name": display, "ordinal": ordinal,
            "country_code": code, "country_name": country_name}


def calculate_stability(db: Session, server_id: int, *, days: int = 7) -> float:
    cutoff = datetime.utcnow().date() - timedelta(days=max(1, days) - 1)
    row = db.execute(
        select(
            func.coalesce(func.sum(ServerMetricDaily.sample_count), 0),
            func.coalesce(func.sum(ServerMetricDaily.online_sample_count), 0),
        ).where(ServerMetricDaily.server_id == server_id,
                ServerMetricDaily.day >= cutoff)
    ).one()
    total, online = int(row[0]), int(row[1])
    if total <= 0:
        return 0.70  # conservative cold-start score
    return max(0.10, min(1.0, online / total))


def update_routing_weight(db: Session, server: Server) -> float:
    """Persist a bounded capacity/stability score used by Xray leastLoad."""
    down = float(getattr(server, "speed_download_mbps", 0) or 0)
    up = float(getattr(server, "speed_upload_mbps", 0) or 0)
    advertised = float(getattr(server, "bandwidth_mbps", 0) or 0)
    if advertised > 0:
        down = down or advertised
        up = up or advertised
    capacity = math.sqrt(max(25.0, down) * max(10.0, up))
    cores = max(1, int(getattr(server, "node_cpu_count", 1) or 1))
    memory_gib = max(0.25, float(getattr(server, "node_mem_total_bytes", 0) or 0) / 2**30)
    resource = min(2.0, max(0.60, math.sqrt(cores) * math.log2(memory_gib + 1) / 2.0))
    stability = calculate_stability(db, server.id)
    latency = max(1.0, float(getattr(server, "speed_latency_ms", 0) or 80.0))
    raw = math.sqrt(capacity / 100.0) * resource * (0.45 + 0.55 * stability) / (
        0.75 + latency / 400.0
    )
    weight = round(max(0.25, min(4.0, raw)), 3)
    server.stability_score = round(stability, 4)
    server.routing_weight = weight
    return weight


def routing_cost(server: Server) -> float:
    weight = max(0.25, min(4.0, float(getattr(server, "routing_weight", 1.0) or 1.0)))
    return round(1.0 / weight, 4)


def _power_key(server: Server) -> tuple[bool, float, float, float, int]:
    return (
        "folder-main" in {tag.casefold() for tag in server_tags(server)},
        float(getattr(server, "routing_weight", 1.0) or 1.0),
        float(getattr(server, "speed_download_mbps", 0) or 0),
        float(getattr(server, "stability_score", 0.7) or 0.7),
        -int(server.id),
    )


def reconcile_folder_group(db: Session, folder: str) -> dict:
    """Refresh subscription-balancer metadata for one country folder.

    Physical nodes always remain ordinary standalone rows in the panel.  The
    subscription service reads ``balance_group``, ``folder_gateway`` and
    ``routing_weight`` and builds the client-side Xray ``leastLoad`` config.
    This function must therefore never hide a node, change its pool tier, or
    turn it into a panel-side balancer.
    """
    folder = (folder or "").strip()
    if not folder:
        return {"folder": "", "gateway_id": None, "member_ids": [], "changed": False}
    all_members = db.scalars(
        select(Server).where(Server.folder == folder).order_by(Server.id)
    ).all()
    members = [
        server for server in all_members
        if (getattr(server, "protocol", "") or "vless-reality") == "vless-reality"
        and (getattr(server, "mode", "") or "standalone") == "standalone"
        and bool(getattr(server, "in_pool", False))
        and "base" not in {tag.casefold() for tag in server_tags(server)}
        and not bool(getattr(server, "tspu_blocked", False))
    ]
    eligible_ids = {server.id for server in members}
    for member in all_members:
        if member.id in eligible_ids:
            continue
        member.balance_group = ""
        member.folder_gateway = False
    for member in members:
        update_routing_weight(db, member)
    if len(members) < 2:
        if members:
            members[0].balance_group = ""
            members[0].folder_gateway = False
        db.flush()
        return {"folder": folder, "gateway_id": None,
                "member_ids": [s.id for s in members], "changed": False}

    # The strongest member supplies the public country name/order. It remains
    # a normal physical server; ``folder_gateway`` is metadata only.
    gateway = max(members, key=_power_key)

    group = f"folder:{folder.casefold()}"[:32]
    for member in members:
        member.balance_group = group
        member.folder_gateway = member.id == gateway.id
    db.flush()
    return {"folder": folder, "gateway_id": gateway.id,
            "member_ids": [s.id for s in members], "changed": True}


def reconcile_all_folder_groups(db: Session) -> list[dict]:
    """Rebuild every existing country folder, including legacy nodes."""
    folders = [
        str(value).strip()
        for value in db.scalars(
            select(Server.folder)
            .where(Server.folder != "")
            .distinct()
            .order_by(Server.folder)
        ).all()
        if str(value or "").strip()
    ]
    return [reconcile_folder_group(db, folder) for folder in folders]

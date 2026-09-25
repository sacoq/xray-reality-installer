"""Scheduled TSPU checks with optional Latency Lab wire verification."""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlsplit

import httpx
from sqlalchemy import case, select

from . import audit as audit_mod
from .database import SessionLocal
from .models import Server, server_tspu_blocked_ips, server_tspu_checked_ips

log = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        return default


CHEBURCHECK_URL = os.environ.get("TSPU_CHECK_URL", "https://cheburcheck.ru/api/v1/check").strip()
LATENCY_LAB_URL = os.environ.get(
    "LATENCY_LAB_API_URL",
    "https://console.latencylab.ru/api/lab/multiscan",
).strip()
LATENCY_LAB_STATS_URL = os.environ.get(
    "LATENCY_LAB_STATS_URL",
    "https://console.latencylab.ru/api/lab/account/stats",
).strip()
LATENCY_LAB_TOKEN = os.environ.get("LATENCY_LAB_API_TOKEN", "").strip()
LATENCY_LAB_COOKIE = os.environ.get("LATENCY_LAB_SESSION_COOKIE", "").strip()
INTERVAL_S = max(60, _env_int("TSPU_CHECK_INTERVAL_S", 3600))
LATENCY_LAB_INTERVAL_S = max(3600, _env_int("LATENCY_LAB_CHECK_INTERVAL_S", 86400))
HTTP_TIMEOUT_S = max(3, _env_int("TSPU_CHECK_HTTP_TIMEOUT_S", 20))
REQUEST_GAP_S = max(2.1, _env_float("TSPU_CHECK_REQUEST_GAP_S", 2.1))
RECOVERY_CONFIRMATIONS = max(2, _env_int("TSPU_RECOVERY_CONFIRMATIONS", 3))
LATENCY_LAB_DAILY_LIMIT = max(1, _env_int("LATENCY_LAB_DAILY_LIMIT", 100))
LATENCY_LAB_RESERVED_URGENT = max(0, _env_int("LATENCY_LAB_RESERVED_URGENT", 25))
LATENCY_LAB_INCIDENT_CACHE_S = max(60, _env_int("LATENCY_LAB_INCIDENT_CACHE_S", 900))
_quota_lock = threading.Lock()
_quota_sync_lock = threading.Lock()
_quota_synced_at = 0.0


def _enabled() -> bool:
    return (os.environ.get("TSPU_CHECK_ENABLED", "1") or "1").lower() not in {"0", "false", "no", "off"}


def _auto_recover() -> bool:
    return (os.environ.get("TSPU_AUTO_RECOVER", "1") or "1").lower() not in {"0", "false", "no", "off"}


def _latency_lab_enabled() -> bool:
    return bool(LATENCY_LAB_URL and (LATENCY_LAB_TOKEN or LATENCY_LAB_COOKIE))


def _primary_bridge_endpoint(server: Server):
    """Match the endpoint advertised to TCP clients, not the backend IP."""
    if str(getattr(server, "protocol", "") or "").lower() == "hysteria2":
        return None
    for binding in getattr(server, "bridge_bindings", None) or []:
        bridge = getattr(binding, "bridge", None)
        if (binding.enabled and bridge and bridge.enabled
                and binding.role == "primary" and bridge.public_host.strip()
                and int(binding.listen_port or 0) > 0):
            return (bridge.public_host.strip().strip("[]"), int(binding.listen_port),
                    bridge.agent_url, bridge.agent_token)
    if (getattr(server, "bridge_enabled", False)
            and str(getattr(server, "bridge_public_host", "") or "").strip()):
        return (server.bridge_public_host.strip().strip("[]"),
                int(server.bridge_port or server.port),
                server.bridge_agent_url, server.bridge_agent_token)
    return None


def _target_for(server: Server) -> str:
    bridge = _primary_bridge_endpoint(server)
    if bridge:
        return bridge[0]
    target = (server.public_host or "").strip().strip("[]")
    if target:
        return target
    return (urlsplit(server.agent_url or "").hostname or "").strip()


def _latency_lab_tcp_port(server: Server) -> int | None:
    """Return a TCP probe port only for TCP-based VPN transports.

    Supplying ``tcp_port`` makes Latency Lab disable its normal dual
    ICMP/TCP wire precheck and test only that TCP port. Hysteria2 is UDP, so
    passing its public/Xray placeholder port produced a false red wire result
    even when the provider's VPN-key test connected successfully.
    """
    if str(getattr(server, "protocol", "") or "").strip().lower() == "hysteria2":
        return None
    bridge = _primary_bridge_endpoint(server)
    if bridge:
        return bridge[1]
    port = int(getattr(server, "port", 0) or 0)
    return port if 1 <= port <= 65535 else None


def _resolve_node_ips(target: str) -> list[str]:
    try:
        values = [str(ipaddress.ip_address(target))]
    except ValueError:
        values = [str(row[4][0]).split("%", 1)[0] for row in socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)]
    result: list[str] = []
    for value in values:
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            continue
        if ip.is_global and str(ip) not in result:
            result.append(str(ip))
    if not result:
        raise LookupError(f"could not resolve public host {target!r}")
    return result


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for nested in value.values():
            yield from _walk(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from _walk(nested)


def parse_latency_lab_wire(payload: Any) -> bool:
    """Read the documented multiscan wire precheck verdict.

    Latency Lab exposes ``result.wire_precheck`` and
    ``result.wire_ok`` for IP multiscan.  Deliberately reject every other
    shape: a successful ICMP/TCP result is not proof of a green wire check.
    """
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("Latency Lab multiscan did not succeed")
    result = payload.get("result")
    if not isinstance(result, dict):
        raise ValueError("Latency Lab response has no result object")
    if result.get("wire_precheck") is not True:
        raise ValueError("Latency Lab did not run the wire precheck")
    verdict = result.get("wire_ok")
    if not isinstance(verdict, bool):
        raise ValueError("Latency Lab response has no wire verdict")
    return verdict


def latency_lab_quota_status() -> dict[str, Any]:
    """Return the panel's UTC-day request accounting without consuming quota."""
    today = datetime.utcnow().date().isoformat()
    key = "latencylab.quota.utc"
    with SessionLocal() as db:
        try:
            state = json.loads(audit_mod.setting_get(db, key, "{}"))
        except (TypeError, ValueError):
            state = {}
        used = int(state.get("used", 0) or 0) if state.get("date") == today else 0
    regular_limit = max(0, LATENCY_LAB_DAILY_LIMIT - LATENCY_LAB_RESERVED_URGENT)
    return {
        "date": today,
        "used": used,
        "limit": LATENCY_LAB_DAILY_LIMIT,
        "reserved_urgent": min(LATENCY_LAB_RESERVED_URGENT, LATENCY_LAB_DAILY_LIMIT),
        "remaining_total": max(0, LATENCY_LAB_DAILY_LIMIT - used),
        "remaining_scheduled": max(0, regular_limit - used),
    }


def seed_latency_lab_used(used: int, *, date: str = "") -> dict[str, Any]:
    """Synchronise today's counter with requests made outside the panel."""
    day = date or datetime.utcnow().date().isoformat()
    value = max(0, min(LATENCY_LAB_DAILY_LIMIT, int(used)))
    with _quota_lock, SessionLocal() as db:
        key = "latencylab.quota.utc"
        try:
            current = json.loads(audit_mod.setting_get(db, key, "{}"))
        except (TypeError, ValueError):
            current = {}
        if current.get("date") == day:
            value = max(value, int(current.get("used", 0) or 0))
        audit_mod.setting_set(db, key, json.dumps({"date": day, "used": value}))
        db.commit()
    return latency_lab_quota_status()


def parse_latency_lab_account_used(payload: Any) -> int:
    """Return the provider's request count for the current UTC window."""
    if not isinstance(payload, dict) or payload.get("ok") is not True:
        raise ValueError("Latency Lab account statistics did not succeed")
    result = payload.get("result")
    window = result.get("window") if isinstance(result, dict) else None
    used = window.get("used") if isinstance(window, dict) else None
    if isinstance(used, bool) or not isinstance(used, (int, float)) or used < 0:
        raise ValueError("Latency Lab account statistics have no request count")
    return int(used)


def sync_latency_lab_quota(
    client: httpx.Client | None = None,
    *,
    force: bool = False,
) -> dict[str, Any]:
    """Merge the official account counter into the panel's local guard."""
    global _quota_synced_at
    if not _latency_lab_enabled() or not LATENCY_LAB_STATS_URL:
        return latency_lab_quota_status()
    now = time.monotonic()
    with _quota_sync_lock:
        if not force and _quota_synced_at and now - _quota_synced_at < 60:
            return latency_lab_quota_status()
        headers: dict[str, str] = {}
        if LATENCY_LAB_TOKEN:
            headers["Authorization"] = f"Bearer {LATENCY_LAB_TOKEN}"
        if LATENCY_LAB_COOKIE:
            headers["Cookie"] = LATENCY_LAB_COOKIE
        owns_client = client is None
        http = client or httpx.Client(timeout=HTTP_TIMEOUT_S, follow_redirects=True)
        try:
            response = http.get(LATENCY_LAB_STATS_URL, headers=headers)
            response.raise_for_status()
            status = seed_latency_lab_used(parse_latency_lab_account_used(response.json()))
            _quota_synced_at = time.monotonic()
            return status
        finally:
            if owns_client:
                http.close()


def _claim_latency_lab_request(reason: str) -> None:
    today = datetime.utcnow().date().isoformat()
    key = "latencylab.quota.utc"
    with _quota_lock, SessionLocal() as db:
        try:
            state = json.loads(audit_mod.setting_get(db, key, "{}"))
        except (TypeError, ValueError):
            state = {}
        used = int(state.get("used", 0) or 0) if state.get("date") == today else 0
        urgent = reason in {"online_drop", "ssh_admission", "manual"}
        ceiling = LATENCY_LAB_DAILY_LIMIT
        if not urgent:
            ceiling -= LATENCY_LAB_RESERVED_URGENT
        if used >= max(0, ceiling):
            raise RuntimeError("Latency Lab daily request budget is exhausted")
        audit_mod.setting_set(db, key, json.dumps({"date": today, "used": used + 1}))
        db.commit()


def _check_ip(
    client: httpx.Client,
    node_ip: str,
    provider: str,
    reason: str,
    *,
    tcp_port: int | None = None,
) -> bool:
    if provider == "latencylab":
        sync_latency_lab_quota(client)
        _claim_latency_lab_request(reason)
        headers: dict[str, str] = {}
        if LATENCY_LAB_TOKEN:
            headers["Authorization"] = f"Bearer {LATENCY_LAB_TOKEN}"
        if LATENCY_LAB_COOKIE:
            headers["Cookie"] = LATENCY_LAB_COOKIE
        request_body: dict[str, Any] = {"text": node_ip}
        if tcp_port and 1 <= int(tcp_port) <= 65535:
            request_body["tcp_port"] = int(tcp_port)
        response = client.post(
            LATENCY_LAB_URL,
            # One multiscan target consumes one request and runs the provider's
            # documented wire precheck before the mobile-operator probes.
            json=request_body,
            headers=headers,
        )
        response.raise_for_status()
        return parse_latency_lab_wire(response.json())
    response = client.get(CHEBURCHECK_URL, params={"target": node_ip})
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict) or not isinstance(payload.get("blocked"), bool):
        raise ValueError("cheburcheck returned an unexpected response")
    return not payload["blocked"]


def _status(server: Server, *, removed: bool = False, restored: bool = False) -> dict:
    provider = getattr(server, "tspu_provider", "") or ""
    wire_ok = provider == "latencylab" and bool(getattr(server, "tspu_wire_ok", False))
    return {
        "server_id": server.id, "target": _target_for(server),
        "provider": provider,
        "wire_ok": wire_ok,
        "wire_status": (("🟢 🔌 wire" if wire_ok else "🔴 🔌 wire")
                        if provider == "latencylab" else ""),
        "blocked": bool(getattr(server, "tspu_blocked", False)),
        "checked_at": getattr(server, "tspu_checked_at", None),
        "checked_ips": server_tspu_checked_ips(server),
        "blocked_ips": server_tspu_blocked_ips(server),
        "error": getattr(server, "tspu_check_error", "") or "",
        "removed_from_pool": removed, "restored_to_pool": restored,
        "clean_streak": int(getattr(server, "tspu_clean_streak", 0) or 0),
        "in_pool": bool(getattr(server, "in_pool", False)),
        "pool_tier": getattr(server, "pool_tier", "") or "",
        "quota": latency_lab_quota_status() if provider == "latencylab" else None,
    }


def check_server_now(server_id: int, *, reason: str = "manual") -> dict:
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        target = _target_for(server)
        tcp_port = _latency_lab_tcp_port(server)
        bridge_endpoint = _primary_bridge_endpoint(server)
        if (
            _latency_lab_enabled()
            and reason == "online_drop"
            and not bridge_endpoint
            and getattr(server, "tspu_provider", "") == "latencylab"
            and getattr(server, "tspu_checked_at", None) is not None
            and server.tspu_checked_at >= datetime.utcnow() - timedelta(seconds=LATENCY_LAB_INCIDENT_CACHE_S)
            and not (getattr(server, "tspu_check_error", "") or "")
        ):
            result = _status(server)
            result["cached"] = True
            return result
    checked_at = datetime.utcnow()
    provider = "latencylab" if _latency_lab_enabled() else "cheburcheck"
    try:
        checked_ips: list[str] = []
        blocked_ips: list[str] = []
        errors: list[str] = []
        with httpx.Client(timeout=HTTP_TIMEOUT_S, follow_redirects=True,
                          headers={"User-Agent": "xnPanel-tspu/2.0"}) as client:
            for index, node_ip in enumerate(_resolve_node_ips(target)):
                if index:
                    time.sleep(REQUEST_GAP_S)
                try:
                    ok = _check_ip(
                        client,
                        node_ip,
                        provider,
                        reason,
                        tcp_port=tcp_port,
                    )
                    checked_ips.append(node_ip)
                    if not ok:
                        blocked_ips.append(node_ip)
                except Exception as exc:  # noqa: BLE001
                    errors.append(f"{node_ip}: {type(exc).__name__}: {exc}")
        if not checked_ips:
            raise RuntimeError("; ".join(errors) or "no IPs were checked")
        blocked = bool(blocked_ips)
        if bridge_endpoint and not blocked:
            from .agent_client import AgentClient
            listeners = AgentClient(bridge_endpoint[2], bridge_endpoint[3]).haproxy_bridges()
            listener = next((row for row in listeners
                             if int(row.get("listen_port") or 0) == tcp_port), {})
            if not listener.get("active") or not listener.get("backend_connected"):
                raise RuntimeError("Bridge-to-node connection is not confirmed; "
                                   "TSPU admission was not changed")
    except Exception as exc:  # provider outage must never eject a node
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            if server is None:
                raise LookupError("server not found") from exc
            server.tspu_checked_at = checked_at
            server.tspu_provider = provider
            server.tspu_check_error = f"{type(exc).__name__}: {exc}"[:2000]
            db.commit()
            return _status(server)

    removed = restored = routing_changed = False
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        if (_target_for(server), _latency_lab_tcp_port(server)) != (target, tcp_port):
            raise RuntimeError("Client endpoint changed during TSPU check; result discarded")
        was_blocked = bool(getattr(server, "tspu_blocked", False))
        server.tspu_checked_at = checked_at
        server.tspu_provider = provider
        # Only Latency Lab can produce the product's green ``wire`` verdict.
        # Cheburcheck remains a compatibility block signal, never an admission proof.
        server.tspu_wire_ok = provider == "latencylab" and not blocked
        server.tspu_blocked = blocked
        routing_changed = blocked != was_blocked
        server.tspu_check_error = "; ".join(errors)[:2000]
        server.tspu_checked_ips = json.dumps(checked_ips, ensure_ascii=False)
        server.tspu_blocked_ips = json.dumps(blocked_ips, ensure_ascii=False)
        if blocked:
            server.tspu_clean_streak = 0
            tier = (getattr(server, "pool_tier", "") or "").strip()
            if tier:
                server.tspu_previous_pool_tier = tier
            if tier or bool(getattr(server, "in_pool", False)):
                server.in_pool = False
                server.pool_tier = ""
                removed = True
            if removed or not was_blocked:
                audit_mod.record(db, user=None, action="server.tspu_blocked",
                    resource_type="server", resource_id=server.id,
                    details=f"{provider}: 🔴 🔌 wire; reason={reason}; target={target}", notify=True)
        else:
            server.tspu_clean_streak = int(getattr(server, "tspu_clean_streak", 0) or 0) + 1
            old_tier = (getattr(server, "tspu_previous_pool_tier", "") or "").strip()
            if old_tier and _auto_recover() and server.tspu_clean_streak >= RECOVERY_CONFIRMATIONS:
                server.pool_tier = old_tier
                server.in_pool = old_tier == "primary"
                server.tspu_previous_pool_tier = ""
                restored = True
                audit_mod.record(db, user=None, action="server.tspu_recovered",
                    resource_type="server", resource_id=server.id,
                    details=f"{provider}: 🟢 🔌 wire x{server.tspu_clean_streak}; restored={old_tier}", notify=True)
        if routing_changed and (getattr(server, "folder", "") or "").strip():
            from .country_groups import reconcile_folder_group
            reconcile_folder_group(db, server.folder)
        db.commit()
        result = _status(server, removed=removed, restored=restored)
    if removed or restored or routing_changed:
        try:
            from .xray_push import rebuild_balancer_configs, rebuild_service_routing_configs
            with SessionLocal() as db:
                for node, exc in rebuild_service_routing_configs(db):
                    log.warning("TSPU service routing rebuild failed for %s: %s", node.id, exc)
                for balancer, exc in rebuild_balancer_configs(db):
                    log.warning("TSPU balancer rebuild failed for %s: %s", balancer.id, exc)
        except Exception:  # noqa: BLE001
            log.exception("TSPU routing rebuild failed for server %s", server_id)
    return result


def _due_server_ids() -> list[int]:
    interval = LATENCY_LAB_INTERVAL_S if _latency_lab_enabled() else INTERVAL_S
    cutoff = datetime.utcnow() - timedelta(seconds=interval)
    with SessionLocal() as db:
        query = select(Server.id).where(
            (Server.tspu_checked_at.is_(None)) | (Server.tspu_checked_at <= cutoff)
        ).order_by(
            case((Server.tspu_checked_at.is_(None), 0), else_=1),
            Server.tspu_checked_at.asc(), Server.id.asc(),
        )
        values = [int(value) for value in db.scalars(query).all()]
    if _latency_lab_enabled():
        values = values[:latency_lab_quota_status()["remaining_scheduled"]]
    return values


class TspuCheckManager:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if not _enabled() or (self._task is not None and not self._task.done()):
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="tspu-check")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    async def _loop(self) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=12)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stopping.is_set():
            try:
                for index, server_id in enumerate(await asyncio.to_thread(_due_server_ids)):
                    if index:
                        await asyncio.sleep(REQUEST_GAP_S)
                    await asyncio.to_thread(check_server_now, server_id, reason="scheduled")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled TSPU sweep failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass


manager = TspuCheckManager()

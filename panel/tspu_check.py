"""Scheduled node-IP checks through LowderPlay/cheburcheck.

Every node is checked once per hour. A positive ``blocked`` verdict removes
the node from both auto-balance tiers, but deliberately keeps the Server row,
clients, tags and traffic history. Recovery does not automatically re-add it:
an administrator must explicitly choose a pool tier again after investigating.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import os
import socket
import time
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlsplit

import httpx
from sqlalchemy import select

from . import audit as audit_mod
from .database import SessionLocal
from .models import Server, server_tspu_blocked_ips, server_tspu_checked_ips


log = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        log.warning("invalid %s, using %s", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, str(default)) or default)
    except (TypeError, ValueError):
        log.warning("invalid %s, using %s", name, default)
        return default


CHEBURCHECK_URL = os.environ.get(
    "TSPU_CHECK_URL", "https://cheburcheck.ru/api/v1/check"
).strip()
INTERVAL_S = max(60, _env_int("TSPU_CHECK_INTERVAL_S", 3600))
HTTP_TIMEOUT_S = max(3, _env_int("TSPU_CHECK_HTTP_TIMEOUT_S", 20))
# Public API default is 30 requests/minute. One node is one request; a 2.1 s
# gap stays under that limit even after rounding/jitter.
REQUEST_GAP_S = max(2.1, _env_float("TSPU_CHECK_REQUEST_GAP_S", 2.1))


def _enabled() -> bool:
    value = (os.environ.get("TSPU_CHECK_ENABLED", "1") or "1").strip().lower()
    return value not in {"0", "false", "no", "off"}


def _target_for(server: Server) -> str:
    target = (server.public_host or "").strip().strip("[]")
    if target:
        return target
    parsed = urlsplit(server.agent_url or "")
    return (parsed.hostname or "").strip()


def _resolve_node_ips(target: str) -> list[str]:
    """Resolve the public host and return unique node IPs (not the domain)."""
    try:
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        pass
    rows = socket.getaddrinfo(target, None, type=socket.SOCK_STREAM)
    out: list[str] = []
    for row in rows:
        value = str(row[4][0]).split("%", 1)[0]
        try:
            value = str(ipaddress.ip_address(value))
        except ValueError:
            continue
        if value not in out:
            out.append(value)
    if not out:
        raise LookupError(f"could not resolve public host {target!r}")
    return out


def _status(server: Server, *, removed_from_pool: bool = False) -> dict:
    return {
        "server_id": server.id,
        "target": _target_for(server),
        "blocked": bool(getattr(server, "tspu_blocked", False)),
        "checked_at": getattr(server, "tspu_checked_at", None),
        "checked_ips": server_tspu_checked_ips(server),
        "blocked_ips": server_tspu_blocked_ips(server),
        "error": getattr(server, "tspu_check_error", "") or "",
        "removed_from_pool": removed_from_pool,
        "in_pool": bool(getattr(server, "in_pool", False)),
        "pool_tier": (getattr(server, "pool_tier", "") or ""),
    }


def check_server_now(server_id: int) -> dict:
    """Check one node and persist its verdict. Safe for API/background use."""
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        target = _target_for(server)
        checked_at = datetime.utcnow()
        if not target:
            server.tspu_checked_at = checked_at
            server.tspu_check_error = "server has no public_host"
            db.commit()
            return _status(server)

    try:
        node_ips = _resolve_node_ips(target)
        checked_ips: list[str] = []
        blocked_ips: list[str] = []
        check_errors: list[str] = []
        with httpx.Client(
            timeout=HTTP_TIMEOUT_S,
            follow_redirects=True,
            headers={"User-Agent": "xnPanel-cheburcheck/1.0"},
        ) as client:
            for index, node_ip in enumerate(node_ips):
                if index:
                    time.sleep(REQUEST_GAP_S)
                try:
                    response = client.get(CHEBURCHECK_URL, params={"target": node_ip})
                    response.raise_for_status()
                    payload = response.json()
                    if not isinstance(payload, dict) or not isinstance(
                        payload.get("blocked"), bool
                    ):
                        raise ValueError("cheburcheck returned an unexpected response")
                except Exception as exc:  # noqa: BLE001
                    check_errors.append(f"{node_ip}: {type(exc).__name__}: {exc}")
                    continue
                response_ips = [
                    str(value) for value in payload.get("ips") or [node_ip] if value
                ]
                for value in response_ips:
                    if value not in checked_ips:
                        checked_ips.append(value)
                if payload["blocked"]:
                    for value in response_ips:
                        if value not in blocked_ips:
                            blocked_ips.append(value)
        if not checked_ips:
            raise RuntimeError("; ".join(check_errors) or "no IPs were checked")
        blocked = bool(blocked_ips)
    except Exception as exc:  # noqa: BLE001
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            if server is None:
                raise LookupError("server not found") from exc
            server.tspu_checked_at = checked_at
            server.tspu_check_error = f"{type(exc).__name__}: {exc}"[:2000]
            db.commit()
            return _status(server)

    removed = False
    was_blocked = False
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        was_blocked = bool(getattr(server, "tspu_blocked", False))
        server.tspu_checked_at = checked_at
        server.tspu_blocked = blocked
        server.tspu_check_error = "; ".join(check_errors)[:2000]
        server.tspu_checked_ips = json.dumps(checked_ips, ensure_ascii=False)
        server.tspu_blocked_ips = json.dumps(blocked_ips, ensure_ascii=False)
        if blocked and (
            bool(getattr(server, "in_pool", False))
            or bool((getattr(server, "pool_tier", "") or "").strip())
        ):
            server.in_pool = False
            server.pool_tier = ""
            removed = True
        if blocked and (removed or not was_blocked):
            audit_mod.record(
                db,
                user=None,
                action="server.tspu_blocked",
                resource_type="server",
                resource_id=server.id,
                details=(
                    f"target={target} ips={','.join(checked_ips) or '-'}; "
                    f"removed_from_pool={removed}"
                ),
                notify=True,
            )
        elif was_blocked and not blocked:
            audit_mod.record(
                db,
                user=None,
                action="server.tspu_clear",
                resource_type="server",
                resource_id=server.id,
                details=f"target={target}; node remains outside the pool",
            )
        db.commit()
        result = _status(server, removed_from_pool=removed)

    if removed:
        try:
            # Import lazily: xray_push imports models and is also used during
            # app startup, while this module is imported by app.py.
            from .xray_push import rebuild_balancer_configs

            with SessionLocal() as db:
                errors = rebuild_balancer_configs(db)
                for balancer, exc in errors:
                    log.warning(
                        "TSPU pool rebuild failed for balancer %s: %s",
                        balancer.id,
                        exc,
                    )
        except Exception:  # noqa: BLE001
            log.exception("TSPU check removed server %s but balancer rebuild failed", server_id)
    return result


def _due_server_ids() -> list[int]:
    cutoff = datetime.utcnow() - timedelta(seconds=INTERVAL_S)
    with SessionLocal() as db:
        return [
            int(value)
            for value in db.scalars(
                select(Server.id)
                .where(
                    (Server.tspu_checked_at.is_(None))
                    | (Server.tspu_checked_at <= cutoff)
                )
                .order_by(Server.id)
            ).all()
        ]


class TspuCheckManager:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if not _enabled():
            log.info("TSPU checker disabled via TSPU_CHECK_ENABLED=0")
            return
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="tspu-check")
        log.info("TSPU checker started: interval=%ss url=%s", INTERVAL_S, CHEBURCHECK_URL)

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
        # Let DB migrations and the other startup managers settle first.
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=12)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stopping.is_set():
            try:
                due = await asyncio.to_thread(_due_server_ids)
                for index, server_id in enumerate(due):
                    if index:
                        await asyncio.sleep(REQUEST_GAP_S)
                    await asyncio.to_thread(check_server_now, server_id)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled TSPU sweep failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass


manager = TspuCheckManager()

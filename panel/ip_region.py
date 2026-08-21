"""Scheduled node-local streaming-service region checks.

Every managed node runs the same commit-pinned ``vernette/ipregion`` probe
through its authenticated agent endpoint.  The panel persists the last good
answer and rebuilds balancer configs only when a routing capability changes.
Transient network errors therefore cannot erase a working route.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Optional

from sqlalchemy import select

from . import audit as audit_mod
from .agent_client import AgentClient
from .database import SessionLocal
from .models import Server, server_ip_region


log = logging.getLogger(__name__)
INTERVAL_S = max(900, int(os.environ.get("IP_REGION_INTERVAL_S", "10800") or 10800))
CONCURRENCY = max(1, min(8, int(os.environ.get("IP_REGION_CONCURRENCY", "3") or 3)))
_BAD_VALUES = {
    "", "n/a", "na", "no", "denied", "failed", "error", "server error",
    "rate-limit", "rate limit", "timeout", "unknown", "null", "none",
}


def service_values(payload: dict[str, Any] | None) -> dict[str, str]:
    out: dict[str, str] = {}
    custom = (((payload or {}).get("results") or {}).get("custom") or [])
    if not isinstance(custom, list):
        return out
    for row in custom:
        if not isinstance(row, dict):
            continue
        name = str(row.get("service") or "").strip().casefold()
        value = str(row.get("ipv4") or "").strip()
        if name:
            out[name] = value
    return out


def routing_capabilities(payload: dict[str, Any] | None) -> dict[str, bool]:
    values = service_values(payload)
    youtube = values.get("youtube", "").strip().upper()
    gemini = values.get("gemini supported", "").strip().casefold()
    tiktok = values.get("tiktok", "").strip()
    return {
        "youtube": youtube == "RU",
        "gemini": gemini in {"yes", "true", "supported"},
        "tiktok": bool(tiktok) and tiktok.casefold() not in _BAD_VALUES
        and tiktok.strip().upper() != "RU",
    }


def _status(server: Server, *, capabilities_changed: bool = False) -> dict:
    payload = server_ip_region(server)
    return {
        "server_id": server.id,
        "checked_at": getattr(server, "ip_region_checked_at", None),
        "error": getattr(server, "ip_region_error", "") or "",
        "ip_region": payload,
        "services": service_values(payload),
        "capabilities": routing_capabilities(payload),
        "capabilities_changed": capabilities_changed,
    }


def check_server_now(server_id: int, *, rebuild: bool = True) -> dict:
    """Run and persist one check while retaining the previous good result."""
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        old_payload = server_ip_region(server)
        agent_url = server.agent_url
        agent_token = server.agent_token

    checked_at = datetime.utcnow()
    try:
        payload = AgentClient(agent_url, agent_token).ip_region()
        # Validate the subset used by routing before it reaches the database.
        if not isinstance(((payload.get("results") or {}).get("custom")), list):
            raise ValueError("agent result has no custom service list")
    except Exception as exc:  # noqa: BLE001
        with SessionLocal() as db:
            server = db.get(Server, server_id)
            if server is None:
                raise LookupError("server not found") from exc
            server.ip_region_checked_at = checked_at
            server.ip_region_error = f"{type(exc).__name__}: {exc}"[:2000]
            db.commit()
            return _status(server)

    changed = routing_capabilities(old_payload) != routing_capabilities(payload)
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise LookupError("server not found")
        server.ip_region_json = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        server.ip_region_checked_at = checked_at
        server.ip_region_error = ""
        if changed:
            audit_mod.record(
                db,
                user=None,
                action="server.ip_region_changed",
                resource_type="server",
                resource_id=server.id,
                details=json.dumps(routing_capabilities(payload), ensure_ascii=False),
            )
        db.commit()
        result = _status(server, capabilities_changed=changed)

    if changed and rebuild:
        try:
            from .xray_push import rebuild_balancer_configs

            with SessionLocal() as db:
                errors = rebuild_balancer_configs(db)
                for balancer, exc in errors:
                    log.warning(
                        "IP-region balancer rebuild failed for %s: %s",
                        balancer.id,
                        exc,
                    )
        except Exception:  # noqa: BLE001
            log.exception("IP-region change on server %s could not rebuild balancers", server_id)
    return result


def _due_server_ids() -> list[int]:
    cutoff = datetime.utcnow() - timedelta(seconds=INTERVAL_S)
    with SessionLocal() as db:
        return [
            int(value)
            for value in db.scalars(
                select(Server.id)
                .where(
                    (Server.ip_region_checked_at.is_(None))
                    | (Server.ip_region_checked_at <= cutoff)
                )
                .order_by(Server.id)
            ).all()
        ]


class IpRegionManager:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="ip-region-check")
        log.info("IP-region checker started: interval=%ss concurrency=%s", INTERVAL_S, CONCURRENCY)

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
            await asyncio.wait_for(self._stopping.wait(), timeout=18)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stopping.is_set():
            try:
                due = await asyncio.to_thread(_due_server_ids)
                semaphore = asyncio.Semaphore(CONCURRENCY)

                async def run_one(server_id: int) -> dict:
                    async with semaphore:
                        return await asyncio.to_thread(
                            check_server_now, server_id, rebuild=False
                        )

                results = await asyncio.gather(*(run_one(server_id) for server_id in due))
                if any(item.get("capabilities_changed") for item in results):
                    from .xray_push import rebuild_balancer_configs

                    def rebuild_once() -> None:
                        with SessionLocal() as db:
                            errors = rebuild_balancer_configs(db)
                            for balancer, exc in errors:
                                log.warning(
                                    "IP-region sweep rebuild failed for %s: %s",
                                    balancer.id,
                                    exc,
                                )

                    await asyncio.to_thread(rebuild_once)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled IP-region sweep failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass


manager = IpRegionManager()

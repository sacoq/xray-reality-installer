"""Background traffic-stats sync.

The panel's per-client ``total_up`` / ``total_down`` columns are the only
source of truth external automation (the xankaVPN bots) reads to detect
abusive subscriptions. Without this loop those columns only get refreshed
when an admin opens ``/api/servers/{id}/stats`` in the UI — i.e. almost
never on a quiet panel — and the abuse bot ends up alerting on stale data.

What this module does:

* Walks every ``Server`` row periodically.
* For each one, calls the agent's ``/stats`` endpoint (which is the wrapper
  around ``xray api statsquery``) and folds the per-email up/down deltas
  into ``Client.total_up`` / ``Client.total_down`` using the same
  ``max(stored, live)`` rule the on-demand ``/api/servers/{id}/stats``
  endpoint uses.
* If a client's quota / expiry trips during the sync (``is_active()``
  flips ``True → False``), we re-push the xray config so xray actually
  drops the over-limit user — same auto-cutoff behaviour the on-demand
  endpoint has.

Why a dedicated loop and not just "let the bot poll ``/stats``":

Each ``/stats`` call ends up running ``xray api statsquery`` on the node,
which briefly ``--reset``-s nothing but still makes xray-core reach into
its stats service. Doing this from N pollers at once on a busy node has
been observed to cause sub-second connection hiccups for end users
(see xankaVPN traffic-monitor commentary). Funneling everything through a
single panel-side loop with explicit pacing means we hit each xray-core
exactly once per ``TRAFFIC_SYNC_INTERVAL_S`` and external readers can
just read ``/api/servers/{id}/clients`` (DB only, zero xray contact).

Configuration via env (all optional, sensible defaults):

* ``TRAFFIC_SYNC_ENABLED`` — ``0`` to disable the loop entirely. Default ``1``.
* ``TRAFFIC_SYNC_INTERVAL_S`` — seconds between full sweeps. Default ``60``.
* ``TRAFFIC_SYNC_PER_SERVER_DELAY_S`` — sleep between consecutive servers
  inside one sweep, so we don't fan out to every node simultaneously.
  Default ``1.0``.
* ``TRAFFIC_SYNC_HTTP_TIMEOUT_S`` — agent HTTP timeout. Default ``15``.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import Optional

from sqlalchemy import select

from .agent_client import AgentClient
from .database import SessionLocal
from .models import Client, Server


log = logging.getLogger(__name__)


def _env_float(name: str, default: float) -> float:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return float(raw)
    except ValueError:
        log.warning("invalid env %s=%r, using default %s", name, raw, default)
        return default


def _env_int(name: str, default: int) -> int:
    raw = (os.environ.get(name, "") or "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        log.warning("invalid env %s=%r, using default %s", name, raw, default)
        return default


def _enabled() -> bool:
    raw = (os.environ.get("TRAFFIC_SYNC_ENABLED", "1") or "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


INTERVAL_S = max(5, _env_int("TRAFFIC_SYNC_INTERVAL_S", 60))
PER_SERVER_DELAY_S = max(0.0, _env_float("TRAFFIC_SYNC_PER_SERVER_DELAY_S", 1.0))
HTTP_TIMEOUT_S = max(1, _env_int("TRAFFIC_SYNC_HTTP_TIMEOUT_S", 15))


def _fmt_stats(raw_stats: list[dict]) -> dict[str, dict[str, int]]:
    """Same parser as ``app._fmt_stats`` — duplicated to avoid an import
    cycle (``app`` imports this module on startup)."""
    out: dict[str, dict[str, int]] = {}
    for item in raw_stats:
        name = item.get("name", "") if isinstance(item, dict) else ""
        try:
            value = int(item.get("value", 0) or 0) if isinstance(item, dict) else 0
        except (TypeError, ValueError):
            value = 0
        if name.startswith("user>>>") and ">>>traffic>>>" in name:
            email = name.split(">>>", 2)[1]
            direction = name.rsplit(">>>", 1)[-1]
            bucket = out.setdefault(email, {"up": 0, "down": 0})
            if direction == "uplink":
                bucket["up"] += value
            elif direction == "downlink":
                bucket["down"] += value
    return out


async def _sync_one_server(server_id: int) -> tuple[int, int]:
    """Refresh ``Client.total_up/down`` for one server.

    Returns ``(updated_count, flipped_count)``. ``flipped_count`` counts
    clients whose ``is_active()`` flipped from True to False as a result
    of this sync (i.e. they just hit a quota / expiry); the caller can
    use that to decide whether to push a new xray config.

    Runs the blocking ``AgentClient.stats`` and the SQLAlchemy session
    inside ``asyncio.to_thread`` so the loop doesn't block other startup
    tasks (the tg-bot manager) on a slow / dead node.
    """

    def _work() -> tuple[int, int, bool, str, int, str]:
        with SessionLocal() as db:
            srv = db.get(Server, server_id)
            if srv is None:
                return 0, 0, False, "", 0, ""
            agent = AgentClient(srv.agent_url, srv.agent_token, timeout=HTTP_TIMEOUT_S)
            try:
                raw = agent.stats(reset=False)
            except Exception as exc:  # noqa: BLE001
                # Treat any failure as "node offline" — we want the loop
                # to keep going for the rest of the fleet rather than
                # crash on a single bad host.
                return 0, 0, False, srv.name, srv.id, f"{type(exc).__name__}: {exc}"
            traffic = _fmt_stats(raw)
            updated = 0
            flipped = 0
            needs_push = False
            for c in srv.clients:
                t = traffic.get(c.email)
                if not t:
                    continue
                was_active = c.is_active()
                new_up = max(int(c.total_up or 0), int(t.get("up", 0) or 0))
                new_down = max(int(c.total_down or 0), int(t.get("down", 0) or 0))
                if new_up != c.total_up or new_down != c.total_down:
                    c.total_up = new_up
                    c.total_down = new_down
                    updated += 1
                if was_active and not c.is_active():
                    flipped += 1
                    needs_push = True
            db.commit()
            return updated, flipped, needs_push, srv.name, srv.id, ""

    updated, flipped, needs_push, name, sid, err = await asyncio.to_thread(_work)
    if err:
        log.info("traffic_sync: server=%s id=%s skipped: %s", name or "?", sid or "?", err)
        return 0, 0
    if needs_push:
        # Push the updated config so xray on the node actually drops
        # over-limit / expired clients we just disabled. Done in a
        # fresh thread because the push code is sync and may itself
        # take a few seconds.
        try:
            await asyncio.to_thread(_repush_config, server_id)
        except Exception as exc:  # noqa: BLE001
            log.warning(
                "traffic_sync: re-push after auto-disable failed for server id=%s: %s",
                server_id,
                exc,
            )
    if updated or flipped:
        log.info(
            "traffic_sync: server=%s id=%s updated=%d auto_disabled=%d",
            name or "?",
            sid or "?",
            updated,
            flipped,
        )
    return updated, flipped


def _repush_config(server_id: int) -> None:
    """Re-build and push xray config for ``server_id``.

    Imported lazily because ``xray_push`` imports ``models`` and we want
    to keep this module's import surface minimal for early startup.
    """
    from .xray_push import push_config

    with SessionLocal() as db:
        srv = db.get(Server, server_id)
        if srv is None:
            return
        push_config(srv, db)


async def _sweep_once() -> dict[str, int]:
    """One full pass over every server."""

    def _list_ids() -> list[int]:
        with SessionLocal() as db:
            return [int(sid) for sid in db.scalars(select(Server.id)).all()]

    ids = await asyncio.to_thread(_list_ids)
    total_updated = 0
    total_flipped = 0
    for i, sid in enumerate(ids):
        if i > 0 and PER_SERVER_DELAY_S > 0:
            await asyncio.sleep(PER_SERVER_DELAY_S)
        try:
            u, f = await _sync_one_server(sid)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001
            log.warning("traffic_sync: server id=%s sync raised: %s", sid, exc)
            continue
        total_updated += u
        total_flipped += f
    return {
        "servers": len(ids),
        "updated": total_updated,
        "auto_disabled": total_flipped,
    }


class TrafficSyncManager:
    """Owns the periodic sync task; mirrors ``tg_bots.manager`` so the
    FastAPI startup hook can do ``await traffic_sync.manager.start()``.
    """

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if not _enabled():
            log.info("traffic_sync: disabled via TRAFFIC_SYNC_ENABLED=0")
            return
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="traffic-sync")
        log.info(
            "traffic_sync: started, interval=%ss per-server-delay=%ss timeout=%ss",
            INTERVAL_S,
            PER_SERVER_DELAY_S,
            HTTP_TIMEOUT_S,
        )

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
        # Tiny startup delay so the panel has finished booting (DB
        # migrations, default-admin seed, tg-bot manager) before we
        # start hitting agents.
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=2.0)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stopping.is_set():
            try:
                summary = await _sweep_once()
                if summary.get("updated") or summary.get("auto_disabled"):
                    log.info("traffic_sync sweep: %s", summary)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                log.warning("traffic_sync sweep failed: %s", exc)
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=INTERVAL_S)
            except asyncio.TimeoutError:
                pass


# Module-level singleton accessed from app.py startup/shutdown hooks.
manager = TrafficSyncManager()

"""Temporary sanctions for Xray-confirmed BitTorrent on restricted nodes."""
from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
import hmac
import logging
import re
from datetime import datetime, timedelta

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select, text
from sqlalchemy.orm import Session

from .auth import current_user
from .database import SessionLocal, get_db
from .models import Client, Server, TorrentNotice, TorrentStrike, TorrentSync, User
from .xray_push import push_config

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/torrent")
_SUB_EMAIL = re.compile(r"^sub_[0-9a-f-]{16,40}_[0-9]+$")


class TorrentHit(BaseModel):
    email: str = Field(min_length=1, max_length=128)
    protocol: str | None = None
    outboundTag: str | None = None
    inboundTag: str | None = None


def _enqueue(db: Session, server_id: int) -> None:
    job = db.get(TorrentSync, server_id)
    if job is None:
        db.add(TorrentSync(server_id=server_id, generation=1))
    else:
        job.generation += 1
        job.retry_after = None


@router.post("/hit")
def receive_hit(
    body: TorrentHit,
    x_xnpanel_agent_token: str = Header(default=""),
) -> dict:
    # Only the protocol rule has a webhook. Never sanction on a port match.
    if body.protocol != "bittorrent" or body.outboundTag != "torrent-guard-block":
        raise HTTPException(status_code=400, detail="not a confirmed BitTorrent route")
    if not x_xnpanel_agent_token:
        raise HTTPException(status_code=401, detail="missing node credential")

    now = datetime.utcnow()
    with SessionLocal() as db:
        # Serialise simultaneous Xray callbacks before reading the strike count.
        db.execute(text("BEGIN IMMEDIATE"))
        host_servers = db.scalars(select(Server)).all()
        host_servers = [s for s in host_servers if hmac.compare_digest(
            str(s.agent_token), x_xnpanel_agent_token
        )]
        if not host_servers:
            raise HTTPException(status_code=401, detail="unknown node credential")
        host_ids = [s.id for s in host_servers if not s.torrent_allowed]
        source = db.scalar(select(Client).where(
            Client.server_id.in_(host_ids), Client.email == body.email
        ).limit(1)) if host_ids else None
        if source is None:
            raise HTTPException(status_code=404, detail="restricted client not found")

        group = body.email.rsplit("_", 1)[0] if _SUB_EMAIL.fullmatch(body.email) else f"client:{source.id}"
        strike = db.get(TorrentStrike, group)
        if strike is not None and strike.frozen_until and strike.frozen_until > now:
            return {"accepted": True, "duplicate": True}
        if strike is None:
            strike = TorrentStrike(group_key=group, strike_count=0)
            db.add(strike)
        strike.strike_count += 1
        strike.last_detected_at = now
        until = now + timedelta(minutes=5 if strike.strike_count == 1 else 60)
        strike.frozen_until = until

        if group.startswith("sub_"):
            clients = db.scalars(select(Client).join(Server).where(
                func.substr(Client.email, 1, len(group) + 1) == group + "_",
                Server.torrent_allowed.is_(False),
            )).all()
        else:
            clients = [source]
        if not clients:
            clients = [source]
        touched = set()
        for client in clients:
            client.torrent_frozen_until = until
            touched.add(client.server_id)
        for server_id in touched:
            _enqueue(db, server_id)
        db.add(TorrentNotice(
            email=body.email, server_id=source.server_id,
            strike_count=strike.strike_count, frozen_until=until,
        ))
        db.commit()
    log.warning("torrent key group frozen: %s nodes=%s strike=%s", group, len(touched), strike.strike_count)
    return {"accepted": True, "strike": strike.strike_count,
            "frozen_until": until.isoformat() + "Z", "nodes": len(touched)}


@router.get("/notices")
def list_notices(
    user: User = Depends(current_user), db: Session = Depends(get_db),
) -> list[dict]:
    del user
    rows = db.scalars(select(TorrentNotice).where(
        TorrentNotice.delivered_at.is_(None)
    ).order_by(TorrentNotice.id).limit(100)).all()
    return [{"id": row.id, "email": row.email, "server_id": row.server_id,
             "strike": row.strike_count,
             "frozen_until": row.frozen_until.isoformat() + "Z"} for row in rows]


@router.post("/notices/{notice_id}/ack")
def ack_notice(
    notice_id: int, user: User = Depends(current_user), db: Session = Depends(get_db),
) -> dict:
    del user
    notice = db.get(TorrentNotice, notice_id)
    if notice is None:
        raise HTTPException(status_code=404, detail="notice not found")
    if notice.delivered_at is None:
        notice.delivered_at = datetime.utcnow()
        db.commit()
    return {"ok": True}


def _sync_job(server_id: int, generation: int) -> None:
    with SessionLocal() as db:
        job = db.get(TorrentSync, server_id)
        if job is None or job.generation != generation:
            return
        server = db.get(Server, server_id)
        if server is None:
            db.delete(job)
            db.commit()
            return
        try:
            push_config(server, db)
        except Exception as exc:
            unreachable = isinstance(exc, (httpx.ConnectError, httpx.ConnectTimeout))
            if unreachable:
                log.warning("torrent sanction node %s unreachable; retrying later", server_id)
            else:
                log.exception("torrent sanction push failed for node %s", server_id)
            with SessionLocal() as retry_db:
                pending = retry_db.get(TorrentSync, server_id)
                if pending is not None and pending.generation == generation:
                    pending.retry_after = datetime.utcnow() + timedelta(
                        minutes=5 if unreachable else 1
                    )
                    retry_db.commit()
            return

    with SessionLocal() as db:
        job = db.get(TorrentSync, server_id)
        if job is not None and job.generation == generation:
            db.delete(job)
            db.commit()


def _reconcile_once() -> None:
    now = datetime.utcnow()
    with SessionLocal() as db:
        expired = db.scalars(select(Client).where(
            Client.torrent_frozen_until.is_not(None),
            Client.torrent_frozen_until <= now,
        ).limit(5000)).all()
        touched = set()
        for client in expired:
            client.torrent_frozen_until = None
            touched.add(client.server_id)
        for server_id in touched:
            _enqueue(db, server_id)
        if expired:
            db.commit()
        jobs = db.scalars(select(TorrentSync).where(or_(
            TorrentSync.retry_after.is_(None), TorrentSync.retry_after <= now
        )).order_by(TorrentSync.server_id).limit(40)).all()
        selected: list[tuple[int, int]] = []
        hosts: set[str] = set()
        for job in jobs:
            server = db.get(Server, job.server_id)
            host = server.agent_url if server else f"missing:{job.server_id}"
            if host in hosts:
                continue
            hosts.add(host)
            selected.append((job.server_id, job.generation))
            if len(selected) == 8:
                break
    if selected:
        with ThreadPoolExecutor(max_workers=len(selected)) as pool:
            list(pool.map(lambda pair: _sync_job(*pair), selected))


class TorrentManager:
    def __init__(self) -> None:
        self.task: asyncio.Task | None = None

    async def start(self) -> None:
        if self.task is None or self.task.done():
            self.task = asyncio.create_task(self._loop(), name="torrent-sanction-sync")

    async def stop(self) -> None:
        if self.task is not None:
            self.task.cancel()
            try:
                await self.task
            except asyncio.CancelledError:
                pass
            self.task = None

    async def _loop(self) -> None:
        while True:
            try:
                await asyncio.to_thread(_reconcile_once)
            except Exception:
                log.exception("torrent sanction reconciliation failed")
            await asyncio.sleep(2)


manager = TorrentManager()

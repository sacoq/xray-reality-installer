"""Shared helpers for pushing xray configs to agents.

Factored out of ``panel.app`` so ``panel.tg_bots`` can use the same
mode-aware logic (standalone vs balancer) without a circular import.
"""
from __future__ import annotations

import logging
import uuid as uuidlib
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from .agent_client import AgentClient, AgentError
from .models import Client, Server
from .xray_config import build_balancer_config, build_config

log = logging.getLogger(__name__)


# Label applied to all Client rows that the panel auto-creates on pool
# upstreams so a balancer node can authenticate its outbounds. Admin UI
# and the TG bot filter rows with this label out of every listing so
# they look invisible to humans.
BALANCER_CLIENT_LABEL = "__balancer__"


def is_balancer(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == "balancer"


def is_service_client(c: Client) -> bool:
    """Return True if a client is a panel-internal balancer auth row."""
    return (c.label or "") == BALANCER_CLIENT_LABEL or (c.email or "").startswith(
        "__balancer__-"
    )


def balancer_client_email(balancer_id: int) -> str:
    return f"__balancer__-{balancer_id}"


def ensure_balancer_upstream_client(
    db: Session, balancer: Server, upstream: Server
) -> Client:
    """Make sure a Client row exists on ``upstream`` that ``balancer``
    can dial to authenticate. Idempotent — returns the existing row if
    present. Caller is expected to commit.
    """
    email = balancer_client_email(balancer.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None:
        return existing
    c = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BALANCER_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(c)
    db.flush()
    return c


def pool_upstreams(db: Session) -> list[Server]:
    """Servers currently usable as balancer upstreams.

    Only ``standalone`` nodes with ``in_pool=True`` participate — a
    balancer can't be an upstream of another balancer (would loop).
    """
    return list(
        db.scalars(
            select(Server)
            .where(Server.in_pool.is_(True))
            .where(Server.mode == "standalone")
            .order_by(Server.id)
        ).all()
    )


def _active_clients_payload(server: Server) -> list[dict]:
    return [
        {"id": c.uuid, "email": c.email, "flow": c.flow}
        for c in server.clients
        if c.is_active()
    ]


def push_standalone_config(server: Server) -> None:
    """Build + push a regular Reality VLESS config for ``server``.

    Service clients (panel-managed balancer auth rows) are included
    alongside real user clients — xray accepts both, admins just don't
    see the service ones in the UI.
    """
    config = build_config(
        port=server.port,
        sni=server.sni,
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
    )
    AgentClient(server.agent_url, server.agent_token).put_config(config)


def push_balancer_config(server: Server, db: Session) -> None:
    """Build + push a balancer config for ``server`` (``mode='balancer'``).

    Walks current pool membership, ensures each upstream has an auth
    client for this balancer (creating missing rows on-the-fly) and
    re-pushes each upstream's xray config so it accepts the new UUID,
    then builds the balancer's own xray config with observatory +
    ``routing.balancers`` leastPing.

    If the pool is empty, the balancer still accepts users but routes
    them direct via ``freedom`` — the admin will notice the
    ``pool members: 0`` badge and flip ``in_pool`` on a standalone
    node.
    """
    upstreams_rows = pool_upstreams(db)
    upstreams_payload: list[dict] = []
    pushed_upstreams: list[Server] = []
    for up in upstreams_rows:
        auth = ensure_balancer_upstream_client(db, server, up)
        upstreams_payload.append(
            {
                "id": up.id,
                "public_host": up.public_host,
                "port": up.port,
                "sni": up.sni,
                "public_key": up.public_key,
                "short_id": up.short_id,
                "auth_uuid": auth.uuid,
            }
        )
        pushed_upstreams.append(up)
    # Commit any newly-created auth clients before we push, so the
    # upstream agents see them too.
    db.commit()
    for up in pushed_upstreams:
        db.refresh(up)
        push_standalone_config(up)

    config = build_balancer_config(
        port=server.port,
        sni=server.sni,
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        upstreams=upstreams_payload,
    )
    AgentClient(server.agent_url, server.agent_token).put_config(config)


def push_config(server: Server, db: Session | None = None) -> None:
    """Push the right xray config for ``server`` based on its ``mode``.

    Balancer pushes require a DB session so we can enumerate pool
    upstreams; pass ``db`` whenever the caller has one.
    """
    if is_balancer(server):
        if db is None:
            raise RuntimeError(
                "balancer push requires a DB session — caller must pass db= "
                "so we can enumerate pool upstreams"
            )
        push_balancer_config(server, db)
    else:
        push_standalone_config(server)


def rebuild_balancer_configs(db: Session) -> list[tuple[Server, Exception]]:
    """Rebuild every balancer's xray config from the current pool set.

    Called from code paths that change which servers are pool members
    or that rotate an upstream's Reality keys. Per-balancer errors are
    collected so one failing balancer doesn't block others.
    """
    errors: list[tuple[Server, Exception]] = []
    for bal in db.scalars(select(Server).where(Server.mode == "balancer")).all():
        try:
            push_balancer_config(bal, db)
        except Exception as exc:  # noqa: BLE001
            errors.append((bal, exc))
            log.warning("balancer push failed for server=%d: %s", bal.id, exc)
    return errors


def delete_balancer_auth_clients(db: Session, balancer_id: int) -> list[Server]:
    """Remove every ``__balancer__-<id>`` auth client on all upstreams
    when a balancer node is deleted. Returns the list of affected
    upstream Server rows so the caller can re-push their configs.
    """
    email = balancer_client_email(balancer_id)
    affected: list[Server] = []
    rows = list(db.scalars(select(Client).where(Client.email == email)).all())
    for row in rows:
        up = db.get(Server, row.server_id)
        if up is not None:
            affected.append(up)
        db.delete(row)
    db.commit()
    return affected


__all__ = [
    "BALANCER_CLIENT_LABEL",
    "AgentError",
    "balancer_client_email",
    "delete_balancer_auth_clients",
    "ensure_balancer_upstream_client",
    "is_balancer",
    "is_service_client",
    "pool_upstreams",
    "push_balancer_config",
    "push_config",
    "push_standalone_config",
    "rebuild_balancer_configs",
]

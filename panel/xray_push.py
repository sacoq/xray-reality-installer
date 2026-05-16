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
from .auto_balance import TIER_FALLBACK, TIER_PRIMARY, server_pool_tier
from .models import Client, Server, server_all_snis
from .xray_config import (
    build_balancer_config,
    build_config,
    build_whitelist_front_config,
)

log = logging.getLogger(__name__)


# Label applied to all Client rows that the panel auto-creates on pool
# upstreams so a balancer node can authenticate its outbounds. Admin UI
# and the TG bot filter rows with this label out of every listing so
# they look invisible to humans.
BALANCER_CLIENT_LABEL = "__balancer__"

# Same idea for ``whitelist-front`` chain nodes: the front needs an auth
# UUID on its foreign upstream, the panel keeps that as a Client row
# tagged with this label so it stays invisible to humans.
BYPASS_CLIENT_LABEL = "__bypass__"

WHITELIST_FRONT_MODE = "whitelist-front"


def is_balancer(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == "balancer"


def is_whitelist_front(server: Server) -> bool:
    return (getattr(server, "mode", "") or "standalone") == WHITELIST_FRONT_MODE


def is_service_client(c: Client) -> bool:
    """Return True if a client is a panel-internal auth row.

    Covers both balancer auth (``__balancer__-<id>``) and whitelist-front
    chain auth (``__bypass__-<id>``).
    """
    label = c.label or ""
    email = c.email or ""
    if label in (BALANCER_CLIENT_LABEL, BYPASS_CLIENT_LABEL):
        return True
    if email.startswith("__balancer__-") or email.startswith("__bypass__-"):
        return True
    return False


def balancer_client_email(balancer_id: int) -> str:
    return f"__balancer__-{balancer_id}"


def bypass_client_email(front_id: int) -> str:
    return f"__bypass__-{front_id}"


def ensure_balancer_upstream_client(
    db: Session, balancer: Server, upstream: Server
) -> tuple[Client, bool]:
    """Make sure a Client row exists on ``upstream`` that ``balancer``
    can dial to authenticate. Idempotent — returns ``(client, created)``
    where ``created`` is ``True`` only when a new row was inserted.
    Caller is expected to commit.

    The ``created`` flag matters because ``push_balancer_config``
    re-pushes every upstream's xray config when this returns, and each
    push restarts xray-core on the node (~10 s of dropped UDP for any
    user connected through it). Only upstreams whose auth set actually
    changed should be re-pushed.
    """
    email = balancer_client_email(balancer.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None:
        return existing, False
    c = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BALANCER_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(c)
    db.flush()
    return c, True


def ensure_bypass_upstream_client(
    db: Session, front: Server, upstream: Server
) -> tuple[Client, bool]:
    """Make sure a Client row exists on ``upstream`` that the
    whitelist-front ``front`` can dial. Idempotent — returns
    ``(client, created)`` so the caller can skip a redundant
    upstream re-push when the auth client was already present.
    Caller commits.
    """
    email = bypass_client_email(front.id)
    existing = db.scalar(
        select(Client).where(Client.server_id == upstream.id, Client.email == email)
    )
    if existing is not None:
        return existing, False
    c = Client(
        server_id=upstream.id,
        uuid=str(uuidlib.uuid4()),
        email=email,
        label=BYPASS_CLIENT_LABEL,
        flow="xtls-rprx-vision",
    )
    db.add(c)
    db.flush()
    return c, True


def pool_upstreams(db: Session) -> list[Server]:
    """Servers currently usable as balancer upstreams.

    Returns every node in any auto-balance tier (``primary`` /
    ``fallback``) that exposes a vless+reality endpoint a balancer can
    dial. That includes:

    * ``standalone`` foreign exits (legacy ``in_pool=True`` or explicit
      ``pool_tier='primary'``).
    * ``standalone`` rows tagged ``pool_tier='fallback'`` (regular
      foreign nodes the admin demoted to fallback duty).
    * ``whitelist-front`` chain nodes tagged ``pool_tier='fallback'``
      — from a balancer's perspective the chain's RU-front IP is just
      another vless+reality endpoint; the chain forwards through to
      its own foreign upstream internally. Without this entry the
      auto-balance "fallback bucket" is invisible to balancer clients
      whenever the admin attaches a foreign upstream to the fallback
      node (which flips its mode away from ``standalone``).

    Balancer rows never participate — a balancer can't be its own
    upstream, that would loop.
    """
    rows = db.scalars(
        select(Server)
        .where(Server.mode != "balancer")
        .order_by(Server.id)
    ).all()
    out: list[Server] = []
    for row in rows:
        # Use the tier helper so the legacy ``in_pool=True`` rows
        # (which may not have an explicit ``pool_tier`` yet) still
        # land in primary, just like the subscription renderer does.
        if server_pool_tier(row) in (TIER_PRIMARY, TIER_FALLBACK):
            out.append(row)
    return out


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
        server_names=server_all_snis(server),
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
    ``routing.balancers`` ``leastLoad`` (primary tier preferred via
    cost penalty on the ``pool-fb-`` prefix; fallback only takes over
    when every primary fails its observatory probe).

    If the pool is empty, the balancer still accepts users but routes
    them direct via ``freedom`` — the admin will notice the
    ``pool members: 0`` badge and flip ``in_pool`` on a standalone
    node.
    """
    upstreams_rows = pool_upstreams(db)
    upstreams_payload: list[dict] = []
    upstreams_to_push: list[Server] = []
    for up in upstreams_rows:
        auth, created = ensure_balancer_upstream_client(db, server, up)
        # ``tier`` drives the outbound tag prefix in
        # ``build_balancer_config`` — fallback rows get the
        # ``pool-fb-<id>`` prefix so the balancer's leastLoad cost
        # rule down-ranks them and primary tier always wins while
        # alive.
        upstreams_payload.append(
            {
                "id": up.id,
                "public_host": up.public_host,
                "port": up.port,
                "sni": up.sni,
                "public_key": up.public_key,
                "short_id": up.short_id,
                "auth_uuid": auth.uuid,
                "tier": server_pool_tier(up),
            }
        )
        # Only re-push upstreams whose user set actually changed (we
        # just inserted a new auth row). Each upstream push restarts
        # xray on that node, so unconditionally re-pushing every pool
        # member on every balancer push amplified routine balancer
        # changes into N user-visible 10 s drops.
        if created:
            upstreams_to_push.append(up)
    # Commit any newly-created auth clients before we push, so the
    # upstream agents see them too.
    db.commit()
    for up in upstreams_to_push:
        db.refresh(up)
        # Mode-aware push so a whitelist-front upstream stays in
        # whitelist-front mode (re-running ``push_standalone_config``
        # on it would erase its bypass routing and downgrade it to a
        # plain foreign exit). ``push_config`` dispatches by mode —
        # standalone → ``push_standalone_config``, whitelist-front →
        # ``push_whitelist_front_config`` — and the latter happens to
        # also re-push the *front's own* upstream (lt.xanka.best
        # etc.), which is harmless when that upstream is also in the
        # balancer pool: the second push is idempotent.
        push_config(up, db)

    config = build_balancer_config(
        port=server.port,
        server_names=server_all_snis(server),
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        upstreams=upstreams_payload,
    )
    AgentClient(server.agent_url, server.agent_token).put_config(config)


def push_whitelist_front_config(server: Server, db: Session) -> None:
    """Build + push a config for ``server`` (``mode='whitelist-front'``).

    Looks up the foreign ``upstream_server_id``, ensures the panel-managed
    ``__bypass__-<front_id>`` Client row exists on it, re-pushes the
    upstream's config so the new auth UUID lands in xray, then builds
    the front's own config with one VLESS+Reality outbound dialing the
    upstream + a single routing rule that funnels every user packet
    into that outbound.

    When ``upstream_server_id`` is unset / dangling, the front still
    accepts users but routes them ``freedom`` from the front itself —
    the UI shows ``upstream: —`` so the admin notices.
    """
    upstream_id = getattr(server, "upstream_server_id", None)
    upstream: Server | None = None
    upstream_payload: dict | None = None
    if upstream_id:
        upstream = db.get(Server, upstream_id)
        # Refuse to chain into another chain — that would loop or fan
        # out endlessly. Only standalone nodes can be foreign exits.
        if upstream is not None and (
            getattr(upstream, "mode", "") or "standalone"
        ) != "standalone":
            log.warning(
                "whitelist-front %d points at non-standalone upstream %d "
                "(mode=%r) — degrading to direct egress",
                server.id, upstream.id, upstream.mode,
            )
            upstream = None
    if upstream is not None:
        auth, created = ensure_bypass_upstream_client(db, server, upstream)
        upstream_payload = {
            "id": upstream.id,
            "public_host": upstream.public_host,
            "port": upstream.port,
            "sni": upstream.sni,
            "public_key": upstream.public_key,
            "short_id": upstream.short_id,
            "auth_uuid": auth.uuid,
        }
        # Commit the new auth row before we push so the upstream sees it.
        db.commit()
        # Only re-push the upstream when we actually changed its user
        # set (newly-inserted bypass auth client). Otherwise the
        # upstream's xray config is already in sync and re-pushing
        # would trigger a needless ``systemctl restart xray`` on the
        # foreign node, dropping every user connected through it.
        if created:
            db.refresh(upstream)
            push_standalone_config(upstream)

    config = build_whitelist_front_config(
        port=server.port,
        server_names=server_all_snis(server),
        dest=server.dest,
        private_key=server.private_key,
        short_ids=[server.short_id],
        clients=_active_clients_payload(server),
        upstream=upstream_payload,
    )
    AgentClient(server.agent_url, server.agent_token).put_config(config)


def push_config(server: Server, db: Session | None = None) -> None:
    """Push the right xray config for ``server`` based on its ``mode``.

    Balancer and whitelist-front pushes require a DB session so the
    panel can enumerate / resolve upstreams. Pass ``db`` whenever the
    caller has one.
    """
    if is_balancer(server):
        if db is None:
            raise RuntimeError(
                "balancer push requires a DB session — caller must pass db= "
                "so we can enumerate pool upstreams"
            )
        push_balancer_config(server, db)
    elif is_whitelist_front(server):
        if db is None:
            raise RuntimeError(
                "whitelist-front push requires a DB session — caller must "
                "pass db= so we can resolve upstream_server_id"
            )
        push_whitelist_front_config(server, db)
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


def delete_bypass_auth_clients(db: Session, front_id: int) -> list[Server]:
    """Remove every ``__bypass__-<id>`` auth client on the upstream
    when a whitelist-front node is deleted. Symmetric to
    ``delete_balancer_auth_clients``. Returns affected upstream rows
    so the caller can re-push their configs.
    """
    email = bypass_client_email(front_id)
    affected: list[Server] = []
    rows = list(db.scalars(select(Client).where(Client.email == email)).all())
    for row in rows:
        up = db.get(Server, row.server_id)
        if up is not None:
            affected.append(up)
        db.delete(row)
    db.commit()
    return affected


def rebuild_whitelist_front_configs(
    db: Session,
    *,
    only_upstream_id: int | None = None,
) -> list[tuple[Server, Exception]]:
    """Rebuild every whitelist-front's xray config.

    Called when an upstream's Reality keys / inbound settings change so
    the chained fronts re-dial with the new credentials. Pass
    ``only_upstream_id`` to only refresh fronts that point at one
    specific upstream (e.g. after rotating that upstream's keys).
    """
    errors: list[tuple[Server, Exception]] = []
    q = select(Server).where(Server.mode == WHITELIST_FRONT_MODE)
    if only_upstream_id is not None:
        q = q.where(Server.upstream_server_id == only_upstream_id)
    for front in db.scalars(q).all():
        try:
            push_whitelist_front_config(front, db)
        except Exception as exc:  # noqa: BLE001
            errors.append((front, exc))
            log.warning(
                "whitelist-front push failed for server=%d: %s", front.id, exc
            )
    return errors


__all__ = [
    "BALANCER_CLIENT_LABEL",
    "BYPASS_CLIENT_LABEL",
    "WHITELIST_FRONT_MODE",
    "AgentError",
    "balancer_client_email",
    "bypass_client_email",
    "delete_balancer_auth_clients",
    "delete_bypass_auth_clients",
    "ensure_balancer_upstream_client",
    "ensure_bypass_upstream_client",
    "is_balancer",
    "is_service_client",
    "is_whitelist_front",
    "pool_upstreams",
    "push_balancer_config",
    "push_config",
    "push_standalone_config",
    "push_whitelist_front_config",
    "rebuild_balancer_configs",
    "rebuild_whitelist_front_configs",
]

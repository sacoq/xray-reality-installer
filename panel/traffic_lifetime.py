"""Durable traffic totals, independent of deletable keys and nodes."""
from sqlalchemy import select, func
from .models import Client, Server, TrafficLifetime


def visible(client):
    return (client.label not in ("__balancer__", "__bypass__")
            and not (client.email or "").startswith(("__balancer__-", "__bypass__-")))


def ensure(db, server):
    row = db.get(TrafficLifetime, server.id)
    if row is None:
        clients = [c for c in server.clients if visible(c)]
        row = TrafficLifetime(server_id=server.id,
            total_up=sum(int(c.total_up or 0) for c in clients),
            total_down=sum(int(c.total_down or 0) for c in clients))
        db.add(row)
        db.flush()
    return row


def seed(db):
    for server in db.scalars(select(Server)).all():
        ensure(db, server)
    db.commit()


def add(row, client, before):
    if visible(client):
        row.total_up += max(0, int(client.total_up or 0) - before[0])
        row.total_down += max(0, int(client.total_down or 0) - before[1])


def totals(db, server_id=0):
    query = select(func.coalesce(func.sum(TrafficLifetime.total_up), 0),
                   func.coalesce(func.sum(TrafficLifetime.total_down), 0))
    if server_id:
        query = query.where(TrafficLifetime.server_id == server_id)
    up, down = db.execute(query).one()
    # Compatibility for an unseeded database; normal startup seeds all nodes.
    existing = set(db.scalars(select(TrafficLifetime.server_id)).all())
    servers = select(Server)
    if server_id:
        servers = servers.where(Server.id == server_id)
    for server in db.scalars(servers).all():
        if server.id not in existing:
            for client in server.clients:
                if visible(client):
                    up += int(client.total_up or 0)
                    down += int(client.total_down or 0)
    return int(up), int(down)

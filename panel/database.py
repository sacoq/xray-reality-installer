"""SQLAlchemy engine / session helpers for the panel."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker


DEFAULT_DB_PATH = "/var/lib/xray-panel/panel.db"
DB_PATH = Path(os.environ.get("PANEL_DB_PATH", DEFAULT_DB_PATH))


class Base(DeclarativeBase):
    pass


def _engine_url() -> str:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return f"sqlite:///{DB_PATH}"


engine = create_engine(
    _engine_url(),
    echo=False,
    future=True,
    connect_args={"check_same_thread": False},
)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False, autoflush=False, future=True)


# Lightweight, idempotent migrations for SQLite. Runs after create_all() and
# only applies ALTER TABLE ADD COLUMN for columns new models have grown.
# SQLite's "ADD COLUMN" supports defaults but not NOT NULL without a default,
# so every migration below has a default or remains NULL.
_COLUMN_MIGRATIONS: list[tuple[str, str, str]] = [
    # (table, column, DDL fragment after "ADD COLUMN")
    ("clients", "data_limit_bytes", "data_limit_bytes INTEGER"),
    ("clients", "expires_at", "expires_at DATETIME"),
    ("clients", "enabled", "enabled BOOLEAN NOT NULL DEFAULT 1"),
    ("users", "totp_secret", "totp_secret VARCHAR(64)"),
    # Per-server display label used in vless:// link names and in the
    # subscription entries. Empty string = fall back to servers.name.
    ("servers", "display_name", "display_name VARCHAR(128) NOT NULL DEFAULT ''"),
    # Part of the auto-balance pool — subscription exposes these under
    # one shared group so clients can auto-select the fastest.
    ("servers", "in_pool", "in_pool BOOLEAN NOT NULL DEFAULT 0"),
    # Subscription customisation — all default to empty / 24h so existing
    # rows keep the previous behaviour.
    ("subscriptions", "profile_title", "profile_title VARCHAR(128) NOT NULL DEFAULT ''"),
    ("subscriptions", "support_url", "support_url VARCHAR(255) NOT NULL DEFAULT ''"),
    ("subscriptions", "announce", "announce TEXT NOT NULL DEFAULT ''"),
    ("subscriptions", "provider_id", "provider_id VARCHAR(64) NOT NULL DEFAULT ''"),
    ("subscriptions", "routing", "routing TEXT NOT NULL DEFAULT ''"),
    ("subscriptions", "update_interval_hours",
     "update_interval_hours INTEGER NOT NULL DEFAULT 24"),
    # Bot-level subscription customisation (applied to every bot-user sub).
    ("tg_bots", "profile_title", "profile_title VARCHAR(128) NOT NULL DEFAULT ''"),
    ("tg_bots", "support_url", "support_url VARCHAR(255) NOT NULL DEFAULT ''"),
    ("tg_bots", "announce", "announce TEXT NOT NULL DEFAULT ''"),
    ("tg_bots", "provider_id", "provider_id VARCHAR(64) NOT NULL DEFAULT ''"),
    ("tg_bots", "routing", "routing TEXT NOT NULL DEFAULT ''"),
    ("tg_bots", "update_interval_hours",
     "update_interval_hours INTEGER NOT NULL DEFAULT 24"),
]


def _run_column_migrations() -> None:
    insp = inspect(engine)
    existing_tables = set(insp.get_table_names())
    with engine.begin() as conn:
        for table, column, ddl in _COLUMN_MIGRATIONS:
            if table not in existing_tables:
                continue
            cols = {c["name"] for c in insp.get_columns(table)}
            if column in cols:
                continue
            conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {ddl}"))


def init_db() -> None:
    # Import models so metadata is populated before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(engine)
    _run_column_migrations()


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

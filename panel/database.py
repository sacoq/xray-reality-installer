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
    # Carry display_name / in_pool through the enrollment flow so a
    # node can be installed with «авто-балансировка» pre-set in one
    # command, without the admin editing the Server row afterwards.
    ("enrollment_tokens", "display_name",
     "display_name VARCHAR(128) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "in_pool",
     "in_pool BOOLEAN NOT NULL DEFAULT 0"),
    # Node mode — ``standalone`` (the default, every existing row) or
    # ``balancer`` (new node type added alongside auto-balance pool).
    # Also accepts ``whitelist-front`` (single-upstream chain — the
    # node forwards every user packet through one specific foreign
    # ``upstream_server_id``, designed for Russian whitelist-bypass
    # setups where the front lives on a whitelisted RU IP).
    ("servers", "mode",
     "mode VARCHAR(32) NOT NULL DEFAULT 'standalone'"),
    ("enrollment_tokens", "mode",
     "mode VARCHAR(32) NOT NULL DEFAULT 'standalone'"),
    # Foreign upstream FK for whitelist-front chain nodes. NULL on every
    # other row. SQLite doesn't enforce FKs we don't ask for, so the
    # ALTER TABLE here is just an INTEGER column — application code is
    # responsible for keeping the reference valid.
    ("servers", "upstream_server_id",
     "upstream_server_id INTEGER"),
    ("enrollment_tokens", "upstream_server_id",
     "upstream_server_id INTEGER"),
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
    # Per-bot custom domain (no port) for /sub/{token} and /page/{token}.
    ("tg_bots", "subscription_domain",
     "subscription_domain VARCHAR(255) NOT NULL DEFAULT ''"),
    # Branding for the HTML subscription page.
    ("tg_bots", "brand_name", "brand_name VARCHAR(128) NOT NULL DEFAULT ''"),
    ("tg_bots", "logo_url", "logo_url VARCHAR(512) NOT NULL DEFAULT ''"),
    ("tg_bots", "page_subtitle", "page_subtitle VARCHAR(255) NOT NULL DEFAULT ''"),
    ("tg_bots", "page_help_text", "page_help_text TEXT NOT NULL DEFAULT ''"),
    ("tg_bots", "page_buy_url", "page_buy_url VARCHAR(512) NOT NULL DEFAULT ''"),
    # Referral programme settings.
    ("tg_bots", "referral_mode", "referral_mode VARCHAR(16) NOT NULL DEFAULT 'off'"),
    ("tg_bots", "referral_levels", "referral_levels INTEGER NOT NULL DEFAULT 1"),
    ("tg_bots", "referral_l1_days", "referral_l1_days INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_l2_days", "referral_l2_days INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_l3_days", "referral_l3_days INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_l1_percent", "referral_l1_percent INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_l2_percent", "referral_l2_percent INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_l3_percent", "referral_l3_percent INTEGER NOT NULL DEFAULT 0"),
    ("tg_bots", "referral_payout_url",
     "referral_payout_url VARCHAR(512) NOT NULL DEFAULT ''"),
    # Referral fields on bot users — track who invited whom, the
    # invitee's own ref code and per-currency partner balances.
    ("tg_bot_users", "referrer_id", "referrer_id INTEGER"),
    ("tg_bot_users", "referral_code",
     "referral_code VARCHAR(32) NOT NULL DEFAULT ''"),
    ("tg_bot_users", "referral_first_payment_done",
     "referral_first_payment_done BOOLEAN NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_balance_stars",
     "referral_balance_stars INTEGER NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_balance_usdt_cents",
     "referral_balance_usdt_cents INTEGER NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_balance_rub_kopecks",
     "referral_balance_rub_kopecks INTEGER NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_total_earned_stars",
     "referral_total_earned_stars INTEGER NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_total_earned_usdt_cents",
     "referral_total_earned_usdt_cents INTEGER NOT NULL DEFAULT 0"),
    ("tg_bot_users", "referral_total_earned_rub_kopecks",
     "referral_total_earned_rub_kopecks INTEGER NOT NULL DEFAULT 0"),
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

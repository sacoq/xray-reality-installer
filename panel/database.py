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
    # Node metadata + per-node WARP routing configuration.
    ("servers", "tags", "tags TEXT NOT NULL DEFAULT '[]'"),
    ("servers", "warp_enabled", "warp_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "warp_domains", "warp_domains TEXT NOT NULL DEFAULT '[]'"),
    # Operator lease metadata and Telegram renewal reminder state.
    ("servers", "hosting_provider", "hosting_provider VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "expires_at", "expires_at DATETIME"),
    ("servers", "notification_bot_id", "notification_bot_id INTEGER"),
    ("servers", "expiry_reminder_sent_for", "expiry_reminder_sent_for DATETIME"),
    ("servers", "expiry_notification_message_id", "expiry_notification_message_id INTEGER"),
    # Scheduled cheburcheck state. A positive result removes the node from
    # auto-balance but leaves the row and its clients intact.
    ("servers", "tspu_blocked", "tspu_blocked BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "tspu_checked_at", "tspu_checked_at DATETIME"),
    ("servers", "tspu_check_error", "tspu_check_error TEXT NOT NULL DEFAULT ''"),
    ("servers", "tspu_checked_ips", "tspu_checked_ips TEXT NOT NULL DEFAULT '[]'"),
    ("servers", "tspu_blocked_ips", "tspu_blocked_ips TEXT NOT NULL DEFAULT '[]'"),
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
    # Multi-SNI support: comma-separated list of extra Reality
    # serverNames the inbound accepts in addition to ``servers.sni``.
    # Per-client pinning lives in ``clients.sni``. Both default to
    # NULL/empty, so existing rows behave exactly as before — nothing
    # changes until an admin actually starts adding SNIs.
    ("servers", "extra_snis",
     "extra_snis TEXT NOT NULL DEFAULT ''"),
    ("clients", "sni", "sni VARCHAR(255)"),
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
    # Auto-balance tier — opt-in priority bucket used by the
    # subscription renderer to build a hierarchical urltest group.
    # ``""`` = not in any tier (default, every existing row), ``primary``
    # = preferred (e.g. foreign exit); ``fallback`` = used when every
    # server in the primary tier is unreachable from the user's
    # network (e.g. whitelist-front nodes hit when the user's region
    # turns the operator whitelist on). Sing-box / Clash subscriptions
    # build a top-level urltest of [primary-pool, fallback-pool] so
    # the client itself fails over and recovers without admin
    # intervention. See ``panel/auto_balance.py`` for the rendering.
    ("servers", "pool_tier",
     "pool_tier VARCHAR(16) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "pool_tier",
     "pool_tier VARCHAR(16) NOT NULL DEFAULT ''"),
    # Reality stream transport (``tcp`` default, ``grpc``, ``xhttp``) and
    # the per-transport extra knob (serviceName for grpc, path for xhttp).
    # Existing rows get ``tcp`` / empty path so the inbound stays
    # byte-identical to what was being pushed before the feature shipped.
    ("servers", "transport",
     "transport VARCHAR(16) NOT NULL DEFAULT 'tcp'"),
    ("servers", "transport_path",
     "transport_path VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "transport",
     "transport VARCHAR(16) NOT NULL DEFAULT 'tcp'"),
    ("enrollment_tokens", "transport_path",
     "transport_path VARCHAR(255) NOT NULL DEFAULT ''"),
    # Protocol-aware nodes. Existing installations remain VLESS+Reality;
    # Hysteria-specific columns are inert until protocol='hysteria2'.
    ("servers", "protocol",
     "protocol VARCHAR(32) NOT NULL DEFAULT 'vless-reality'"),
    ("enrollment_tokens", "protocol",
     "protocol VARCHAR(32) NOT NULL DEFAULT 'vless-reality'"),
    ("servers", "hysteria_listen",
     "hysteria_listen VARCHAR(128) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_listen",
     "hysteria_listen VARCHAR(128) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_auth_mode",
     "hysteria_auth_mode VARCHAR(16) NOT NULL DEFAULT 'userpass'"),
    ("enrollment_tokens", "hysteria_auth_mode",
     "hysteria_auth_mode VARCHAR(16) NOT NULL DEFAULT 'userpass'"),
    ("servers", "hysteria_auth_password",
     "hysteria_auth_password VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_auth_password",
     "hysteria_auth_password VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_tls_mode",
     "hysteria_tls_mode VARCHAR(16) NOT NULL DEFAULT 'acme'"),
    ("enrollment_tokens", "hysteria_tls_mode",
     "hysteria_tls_mode VARCHAR(16) NOT NULL DEFAULT 'acme'"),
    ("servers", "hysteria_acme_email",
     "hysteria_acme_email VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_acme_email",
     "hysteria_acme_email VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_cert_path",
     "hysteria_cert_path VARCHAR(512) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_cert_path",
     "hysteria_cert_path VARCHAR(512) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_key_path",
     "hysteria_key_path VARCHAR(512) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_key_path",
     "hysteria_key_path VARCHAR(512) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_obfs_type",
     "hysteria_obfs_type VARCHAR(16) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_obfs_type",
     "hysteria_obfs_type VARCHAR(16) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_obfs_password",
     "hysteria_obfs_password VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_obfs_password",
     "hysteria_obfs_password VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_up_mbps",
     "hysteria_up_mbps INTEGER NOT NULL DEFAULT 0"),
    ("enrollment_tokens", "hysteria_up_mbps",
     "hysteria_up_mbps INTEGER NOT NULL DEFAULT 0"),
    ("servers", "hysteria_down_mbps",
     "hysteria_down_mbps INTEGER NOT NULL DEFAULT 0"),
    ("enrollment_tokens", "hysteria_down_mbps",
     "hysteria_down_mbps INTEGER NOT NULL DEFAULT 0"),
    ("servers", "hysteria_ignore_client_bandwidth",
     "hysteria_ignore_client_bandwidth BOOLEAN NOT NULL DEFAULT 0"),
    ("enrollment_tokens", "hysteria_ignore_client_bandwidth",
     "hysteria_ignore_client_bandwidth BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "hysteria_congestion",
     "hysteria_congestion VARCHAR(16) NOT NULL DEFAULT 'bbr'"),
    ("enrollment_tokens", "hysteria_congestion",
     "hysteria_congestion VARCHAR(16) NOT NULL DEFAULT 'bbr'"),
    ("servers", "hysteria_bbr_profile",
     "hysteria_bbr_profile VARCHAR(16) NOT NULL DEFAULT 'standard'"),
    ("enrollment_tokens", "hysteria_bbr_profile",
     "hysteria_bbr_profile VARCHAR(16) NOT NULL DEFAULT 'standard'"),
    ("servers", "hysteria_disable_udp",
     "hysteria_disable_udp BOOLEAN NOT NULL DEFAULT 0"),
    ("enrollment_tokens", "hysteria_disable_udp",
     "hysteria_disable_udp BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "hysteria_udp_idle_timeout",
     "hysteria_udp_idle_timeout INTEGER NOT NULL DEFAULT 60"),
    ("enrollment_tokens", "hysteria_udp_idle_timeout",
     "hysteria_udp_idle_timeout INTEGER NOT NULL DEFAULT 60"),
    ("servers", "hysteria_masquerade_url",
     "hysteria_masquerade_url VARCHAR(512) NOT NULL DEFAULT 'https://news.ycombinator.com/'"),
    ("enrollment_tokens", "hysteria_masquerade_url",
     "hysteria_masquerade_url VARCHAR(512) NOT NULL DEFAULT 'https://news.ycombinator.com/'"),
    ("servers", "hysteria_stats_secret",
     "hysteria_stats_secret VARCHAR(128) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_stats_secret",
     "hysteria_stats_secret VARCHAR(128) NOT NULL DEFAULT ''"),
    ("servers", "hysteria_stats_port",
     "hysteria_stats_port INTEGER NOT NULL DEFAULT 9999"),
    ("enrollment_tokens", "hysteria_stats_port",
     "hysteria_stats_port INTEGER NOT NULL DEFAULT 9999"),
    ("servers", "hysteria_advanced_json",
     "hysteria_advanced_json TEXT NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "hysteria_advanced_json",
     "hysteria_advanced_json TEXT NOT NULL DEFAULT ''"),
    # Managed local TLS fallback used as a first-party Reality SNI target.
    ("servers", "sni_endpoint_enabled",
     "sni_endpoint_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ("enrollment_tokens", "sni_endpoint_enabled",
     "sni_endpoint_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "sni_endpoint_domain",
     "sni_endpoint_domain VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "sni_endpoint_domain",
     "sni_endpoint_domain VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "sni_endpoint_email",
     "sni_endpoint_email VARCHAR(255) NOT NULL DEFAULT ''"),
    ("enrollment_tokens", "sni_endpoint_email",
     "sni_endpoint_email VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "sni_endpoint_port",
     "sni_endpoint_port INTEGER NOT NULL DEFAULT 9443"),
    ("enrollment_tokens", "sni_endpoint_port",
     "sni_endpoint_port INTEGER NOT NULL DEFAULT 9443"),
    ("servers", "bridge_enabled",
     "bridge_enabled BOOLEAN NOT NULL DEFAULT 0"),
    ("servers", "bridge_name",
     "bridge_name VARCHAR(128) NOT NULL DEFAULT ''"),
    ("servers", "bridge_public_host",
     "bridge_public_host VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "bridge_port",
     "bridge_port INTEGER NOT NULL DEFAULT 443"),
    ("servers", "bridge_agent_url",
     "bridge_agent_url VARCHAR(255) NOT NULL DEFAULT ''"),
    ("servers", "bridge_agent_token",
     "bridge_agent_token VARCHAR(255) NOT NULL DEFAULT ''"),
    # Existing-config nodes and observability metadata.
    ("servers", "custom_inbound_tag",
     "custom_inbound_tag VARCHAR(128) NOT NULL DEFAULT ''"),
    ("servers", "bandwidth_mbps",
     "bandwidth_mbps FLOAT NOT NULL DEFAULT 0"),
    ("servers", "speed_download_mbps",
     "speed_download_mbps FLOAT NOT NULL DEFAULT 0"),
    ("servers", "speed_upload_mbps",
     "speed_upload_mbps FLOAT NOT NULL DEFAULT 0"),
    ("servers", "speed_latency_ms",
     "speed_latency_ms FLOAT NOT NULL DEFAULT 0"),
    ("servers", "speed_tested_at", "speed_tested_at DATETIME"),
    ("servers", "speed_test_error",
     "speed_test_error TEXT NOT NULL DEFAULT ''"),
    # Raw xray baselines used to accumulate traffic correctly after a core
    # restart resets its in-memory counters.
    ("clients", "xray_up_baseline", "xray_up_baseline INTEGER"),
    ("clients", "xray_down_baseline", "xray_down_baseline INTEGER"),
    # Provisioned subscriptions own one generated key per selected node.
    # Existing subscriptions remain legacy aggregations until explicitly
    # recreated; the nullable owner column keeps all their clients untouched.
    ("clients", "subscription_id", "subscription_id INTEGER"),
    ("subscriptions", "provisioned",
     "provisioned BOOLEAN NOT NULL DEFAULT 0"),
    # Uptime root-cause telemetry. Existing samples remain readable; blank
    # failure_kind means the sample predates cause tracking.
    ("server_metric_samples", "failure_kind",
     "failure_kind VARCHAR(24) NOT NULL DEFAULT ''"),
    ("server_metric_samples", "failure_detail",
     "failure_detail TEXT NOT NULL DEFAULT ''"),
    ("server_metric_samples", "response_ms",
     "response_ms FLOAT NOT NULL DEFAULT 0"),
    ("server_metric_daily", "online_sample_count",
     "online_sample_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "xray_failure_count",
     "xray_failure_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "network_failure_count",
     "network_failure_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "node_failure_count",
     "node_failure_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "agent_failure_count",
     "agent_failure_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "unknown_failure_count",
     "unknown_failure_count INTEGER NOT NULL DEFAULT 0"),
    ("server_metric_daily", "response_ms_sum",
     "response_ms_sum FLOAT NOT NULL DEFAULT 0"),
    ("server_metric_daily", "response_ms_min",
     "response_ms_min FLOAT NOT NULL DEFAULT 0"),
    ("server_metric_daily", "response_ms_max",
     "response_ms_max FLOAT NOT NULL DEFAULT 0"),
    ("server_metric_daily", "response_sample_count",
     "response_sample_count INTEGER NOT NULL DEFAULT 0"),
]


# Post-migration data backfills. Each entry is a SQL UPDATE that runs
# only after the columns it touches are guaranteed to exist (i.e. the
# ALTER TABLE ADD COLUMN above already ran). Idempotent — re-running
# the panel doesn't double-apply (the WHERE clause excludes already-
# updated rows).
_DATA_BACKFILLS: list[tuple[str, str, str]] = [
    # Bridge legacy ``in_pool=True`` rows into the new ``pool_tier``
    # taxonomy. Existing pool members were always primary-tier (the
    # only tier that existed before fallback shipped), so this is a
    # safe one-shot map.
    (
        "servers",
        "pool_tier",
        "UPDATE servers SET pool_tier = 'primary' "
        "WHERE pool_tier = '' AND in_pool = 1 AND mode = 'standalone'",
    ),
    (
        "enrollment_tokens",
        "pool_tier",
        "UPDATE enrollment_tokens SET pool_tier = 'primary' "
        "WHERE pool_tier = '' AND in_pool = 1 AND mode = 'standalone'",
    ),
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
        # Existing SQLite databases do not get new SQLAlchemy table
        # constraints from create_all(). Enforce the one-key-per-node
        # subscription invariant with a partial unique index (NULL legacy
        # clients remain unrestricted).
        insp = inspect(engine)
        if "clients" in set(insp.get_table_names()):
            client_columns = {c["name"] for c in insp.get_columns("clients")}
            if "subscription_id" in client_columns:
                conn.execute(
                    text(
                        "CREATE UNIQUE INDEX IF NOT EXISTS "
                        "uq_client_subscription_server "
                        "ON clients(subscription_id, server_id) "
                        "WHERE subscription_id IS NOT NULL"
                    )
                )
        # Run data backfills only for tables/columns that exist now.
        insp = inspect(engine)
        for table, column, sql in _DATA_BACKFILLS:
            if table not in set(insp.get_table_names()):
                continue
            cols = {c["name"] for c in insp.get_columns(table)}
            if column not in cols:
                continue
            conn.execute(text(sql))


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

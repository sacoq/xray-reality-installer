"""DB models for the panel."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    # TOTP (RFC 6238) base32 secret. When set, the user must present a valid
    # 6-digit code at login in addition to username/password.
    totp_secret: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class AuditLog(Base):
    """Audit trail of admin actions.

    Every mutating endpoint writes one row. Kept deliberately narrow — the
    panel doesn't need full event sourcing, just an "who did what, when"
    view for operations. ``details`` is a short human-readable string; for
    structured payloads use a JSON blob.
    """

    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Nullable so automated/system actions (e.g. scheduled disables) are
    # representable without a fake user row.
    user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    username: Mapped[str] = mapped_column(String(64), nullable=False, default="system")
    action: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    resource_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    details: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )


class Server(Base):
    """A managed xray node."""

    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # host/port used to reach the agent (e.g. http://1.2.3.4:8765)
    agent_url: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_token: Mapped[str] = mapped_column(String(255), nullable=False)

    # Human-readable override used in vless:// link labels and subscription
    # entries. When empty, fall back to ``name``. This lets admins/bots
    # relabel a server in every subscription without renaming the panel-side
    # identity (which is referenced by tg_bot_servers, foreign keys, audit
    # trail, etc).
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")

    # xray-side inbound settings for this node
    public_host: Mapped[str] = mapped_column(String(255), nullable=False)  # used to build vless:// links
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    sni: Mapped[str] = mapped_column(String(255), nullable=False, default="rutube.ru")
    dest: Mapped[str] = mapped_column(String(255), nullable=False, default="rutube.ru:443")
    private_key: Mapped[str] = mapped_column(String(255), nullable=False)
    public_key: Mapped[str] = mapped_column(String(255), nullable=False)
    short_id: Mapped[str] = mapped_column(String(64), nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)

    clients: Mapped[list["Client"]] = relationship(
        back_populates="server", cascade="all, delete-orphan", order_by="Client.id"
    )


class Client(Base):
    """A VLESS client (key) bound to a server."""

    __tablename__ = "clients"
    __table_args__ = (UniqueConstraint("server_id", "email", name="uq_client_server_email"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    server_id: Mapped[int] = mapped_column(ForeignKey("servers.id", ondelete="CASCADE"), nullable=False)

    uuid: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    email: Mapped[str] = mapped_column(String(128), nullable=False)  # xray uses this as the stat key
    label: Mapped[str] = mapped_column(String(128), nullable=False, default="xray-reality")
    flow: Mapped[str] = mapped_column(String(64), nullable=False, default="xtls-rprx-vision")

    # Cumulative traffic (bytes) reset counters integrate into these; they never decrease.
    total_up: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    total_down: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Marzban-style quotas. When any of these trip the client is dropped from the
    # xray config push and its subscription entry is skipped — the row stays in
    # the DB so the admin can bump the limit / extend the expiry and re-enable.
    data_limit_bytes: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # Hard admin switch — overrides expiry/limit. Disabled clients never
    # appear in xray config regardless of other state.
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)

    server: Mapped[Server] = relationship(back_populates="clients")

    # ---- derived ----
    def total_bytes(self) -> int:
        return int((self.total_up or 0) + (self.total_down or 0))

    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires_at is None:
            return False
        return (now or datetime.utcnow()) >= self.expires_at

    def is_over_limit(self) -> bool:
        if not self.data_limit_bytes:
            return False
        return self.total_bytes() >= int(self.data_limit_bytes)

    def is_active(self, now: Optional[datetime] = None) -> bool:
        """Whether the client should be present in the pushed xray config."""
        if not self.enabled:
            return False
        if self.is_expired(now):
            return False
        if self.is_over_limit():
            return False
        return True


class ApiToken(Base):
    """Bearer token for programmatic panel access.

    Unlike session cookies, API tokens don't expire and are returned in
    plaintext only once on creation (the admin must copy it — the stored
    value is never shown again). Used for bots, automation, external
    integrations. Every token is owned by a user, and inherits their
    admin privileges.
    """

    __tablename__ = "api_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)


class Setting(Base):
    """Simple key/value for panel-wide settings."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")


class EnrollmentToken(Base):
    """One-time enrollment for a new node.

    The admin creates an enrollment in the panel to get a copy-pastable install
    command. The installer on the new box uses the token to fetch the intended
    inbound settings (name/port/sni/dest/agent_token) and to register itself.
    """

    __tablename__ = "enrollment_tokens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Opaque token the installer sends back. Secret.
    token: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    # Intended server name in the panel (unique among servers).
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    # Public host used in vless:// links. May be empty — installer will substitute
    # --domain or the public IP it detects.
    public_host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=443)
    sni: Mapped[str] = mapped_column(String(255), nullable=False, default="rutube.ru")
    dest: Mapped[str] = mapped_column(String(255), nullable=False, default="rutube.ru:443")
    # Agent-side.
    agent_port: Mapped[int] = mapped_column(Integer, nullable=False, default=8765)
    agent_token: Mapped[str] = mapped_column(String(96), nullable=False)
    # Lifecycle.
    used_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    server_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


# Many-to-many between subscriptions and clients.
subscription_clients = Table(
    "subscription_clients",
    Base.metadata,
    Column(
        "subscription_id",
        Integer,
        ForeignKey("subscriptions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "client_id",
        Integer,
        ForeignKey("clients.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# Which servers a bot hands out keys for. When non-empty, /start issues
# one VLESS client per server and the subscription returns one vless://
# link per (user, server). Empty set = fall back to ``TgBot.default_server_id``.
tg_bot_servers = Table(
    "tg_bot_servers",
    Base.metadata,
    Column(
        "bot_id",
        Integer,
        ForeignKey("tg_bots.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "server_id",
        Integer,
        ForeignKey("servers.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


# All xnPanel clients issued to a single bot user — one row per server the
# bot is configured for. Legacy single-server bots still have their
# ``TgBotUser.client_id`` for backward compat; multi-server bots rely on
# this junction.
tg_bot_user_clients = Table(
    "tg_bot_user_clients",
    Base.metadata,
    Column(
        "bot_user_id",
        Integer,
        ForeignKey("tg_bot_users.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "client_id",
        Integer,
        ForeignKey("clients.id", ondelete="CASCADE"),
        primary_key=True,
    ),
)


class TgBot(Base):
    """A Telegram bot that hands out vless subscriptions to end users.

    The panel runs one aiogram polling task per bot in-process; the token
    is stored plaintext because the panel must be able to hand it to
    aiogram on every restart. Admins can toggle ``enabled`` without
    deleting the bot (stops the polling task, keeps users + fingerprints).
    """

    __tablename__ = "tg_bots"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    bot_token: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # Telegram user id that gets anti-fraud notifications; usually the
    # owner of the bot. Extracted from @userinfobot.
    owner_chat_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    welcome_text: Mapped[str] = mapped_column(
        Text, nullable=False, default=""
    )
    # Which server every new user's key lands on. Null = random among
    # enabled servers at /start time.
    default_server_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
    # New-user key lifetime in days (0 = no expiry); data limit in bytes
    # (0 = unlimited). These map 1:1 onto Client.expires_at / data_limit_bytes.
    default_days: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    default_data_limit_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Anti-fraud threshold: unique device fingerprints (UA) observed on the
    # key's subscription link over the last 24h. When exceeded, the panel
    # pings owner_chat_id with a ban/ignore inline keyboard. 0 disables.
    device_limit: Mapped[int] = mapped_column(Integer, nullable=False, default=3)

    # Subscription customisation applied to every bot-user's /sub/{token}
    # response. Mirrors the fields on Subscription but scoped to this bot
    # so the admin can tweak Happ/v2rayN metadata (profile title, provider
    # ID, routing URL, support URL, announce banner, refresh interval)
    # without editing every Subscription row. ``profile_title`` supports
    # ``{username}``/``{tg_user_id}`` placeholders — when empty, defaults
    # to ``xnPanel · @<username>``. See tg_bots._format_mysub /
    # _apply_subscription_extras for how these are injected.
    profile_title: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    support_url: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    announce: Mapped[str] = mapped_column(Text, nullable=False, default="")
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    routing: Mapped[str] = mapped_column(Text, nullable=False, default="")
    update_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    users: Mapped[list["TgBotUser"]] = relationship(
        back_populates="bot", cascade="all, delete-orphan", order_by="TgBotUser.id"
    )
    # Explicit server set. Empty = legacy single-server mode driven by
    # ``default_server_id`` (or random fallback).
    servers: Mapped[list[Server]] = relationship(
        secondary=tg_bot_servers, lazy="selectin"
    )


class TgBotUser(Base):
    """A Telegram user onboarded through a bot.

    Links a Telegram user id to exactly one xnPanel ``Client`` (the issued
    key). Stored per bot so the same human using two bots is represented
    twice — different owners, different thresholds.
    """

    __tablename__ = "tg_bot_users"
    __table_args__ = (
        UniqueConstraint("bot_id", "tg_user_id", name="uq_tg_bot_user"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bot_id: Mapped[int] = mapped_column(
        ForeignKey("tg_bots.id", ondelete="CASCADE"), nullable=False
    )
    tg_user_id: Mapped[str] = mapped_column(String(32), nullable=False)
    tg_username: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    first_name: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    # Per-bot subscription token: the end user's aggregated feed (only
    # contains their client). Public, unguessable.
    sub_token: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    # The xnPanel client handed out on /start.
    client_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("clients.id", ondelete="SET NULL"), nullable=True
    )
    # Admin block (overrides enabled state on the Client too).
    banned: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_alert_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    bot: Mapped[TgBot] = relationship(back_populates="users")
    # All clients issued for this bot user (one per server the bot covers).
    # When the list is empty but ``client_id`` is set, treat that legacy
    # single-server client as the implicit set of one.
    clients: Mapped[list["Client"]] = relationship(
        secondary=tg_bot_user_clients, lazy="selectin"
    )


class DeviceFingerprint(Base):
    """One row per (subscription fetch) — the anti-fraud signal source.

    The endpoint hashes user-agent + remote IP into a compact key; rows
    older than 24h are dropped by the periodic check. Count of distinct
    fingerprints in the window = "how many devices use this key".
    """

    __tablename__ = "device_fingerprints"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # Either a bot-user sub_token or a panel-admin Subscription.token.
    sub_token: Mapped[str] = mapped_column(
        String(64), nullable=False, index=True
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    user_agent: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    ip: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )


class Subscription(Base):
    """Aggregated subscription: a URL that returns vless links across servers.

    If ``include_all`` is true, every current client in the DB is included in
    the feed (useful for admin "master" subscriptions). Otherwise, only the
    clients linked via ``clients`` are included.
    """

    __tablename__ = "subscriptions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    token: Mapped[str] = mapped_column(String(96), unique=True, nullable=False)
    include_all: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Customisation fields exposed to VPN clients (Happ / v2rayN / Hiddify /
    # sing-box). All optional — empty string = "use the panel default".
    # ``profile_title`` overrides the ``Profile-Title`` header (defaults to
    # ``name``). ``support_url`` fills ``Support-Url`` (``support-url``).
    # ``announce`` is prepended to the plaintext vless:// list as a
    # ``#announce: …`` line so clients can show a banner.
    # ``provider_id`` is both the ``X-Provider-ID`` header and a
    # ``providerid: …`` body line Happ reads for multi-provider routing.
    # ``routing`` is an optional ``happ://routing/…`` URL emitted as the
    # ``Routing`` header — lets admins ship pre-baked routing rules.
    # ``update_interval_hours`` drives ``Profile-Update-Interval``.
    profile_title: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    support_url: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    announce: Mapped[str] = mapped_column(Text, nullable=False, default="")
    provider_id: Mapped[str] = mapped_column(String(64), nullable=False, default="")
    routing: Mapped[str] = mapped_column(Text, nullable=False, default="")
    update_interval_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=24)

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    clients: Mapped[list["Client"]] = relationship(
        "Client",
        secondary=subscription_clients,
        backref="subscriptions",
    )

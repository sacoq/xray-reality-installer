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

    # Opt-in flag: when True, this server is part of the auto-balance
    # pool. The subscription builder marks these entries with a
    # ``⚡`` prefix (so Hiddify / v2rayNG / Karing / Happ group them)
    # and, for sing-box subscriptions, adds an ``urltest`` outbound
    # that picks the lowest-latency pool node. Non-pool servers are
    # still exposed as individual entries alongside, so users can
    # manually connect to a specific node when they want to.
    in_pool: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    # Node mode. ``standalone`` = regular Reality VLESS terminator (the
    # default — every node behaves this way). ``balancer`` = a node
    # whose xray has one user-facing inbound plus N outbounds to every
    # server with ``in_pool=True``; routing picks the lowest-ping
    # upstream via xray's observatory + ``strategy.leastPing``. A
    # balancer node gives users a **single** vless key that internally
    # routes them to the fastest pool member, instead of relying on
    # client-side urltest.
    #
    # ``whitelist-front`` = a single-upstream chain. The node has the
    # usual VLESS+Reality user-facing inbound, but every byte of user
    # traffic is forwarded over a second VLESS+Reality outbound to a
    # specific ``upstream_server_id`` (a regular ``standalone`` server).
    # Designed for Russian "whitelist bypass" setups: the front lives on
    # a Russian DC IP that is on operator whitelists (so ТСПУ does not
    # throttle the user's connection), and every packet exits the
    # internet from the foreign upstream. End users only ever see the
    # RU front — they don't know about the upstream.
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="standalone")

    # When ``mode='whitelist-front'`` this points to the Server row that
    # plays the role of the foreign upstream / exit. The panel
    # auto-provisions a ``__bypass__-<front_id>`` Client on the
    # upstream so the front can authenticate when dialing it. Null for
    # every other mode.
    upstream_server_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )

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
    # Pre-set display_name — applied to the Server row on successful
    # enrollment. Empty = fall back to ``name``. Lets admin pick the
    # user-facing label (e.g. "🇩🇪 Германия 1") up-front instead of
    # editing it after the node registers.
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    # Pre-set pool membership — applied to the Server row. The only way
    # to turn this on from the UI is via the dedicated «Новая нода
    # авто-балансировки» button; the plain enrollment flow leaves it
    # off.
    in_pool: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Pre-set node mode — applied to the Server on enrollment. The
    # dashboard's «🎯 Балансер-нода» button sets this to ``balancer``;
    # the «🇷🇺→🌍 Нода обхода (whitelist)» button sets it to
    # ``whitelist-front``; everything else leaves it as ``standalone``.
    mode: Mapped[str] = mapped_column(String(32), nullable=False, default="standalone")
    # When the enrolled node is a whitelist-front, this is the foreign
    # upstream Server.id picked at enrollment-time; the panel writes it
    # onto the new Server row on completion so the chain wiring is
    # already correct on the very first config push.
    upstream_server_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("servers.id", ondelete="SET NULL"), nullable=True
    )
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

    # Per-bot public domain for subscription/page links (no port). When
    # set, /sub/{token} and /page/{token} URLs handed to the user are
    # built from this prefix instead of the global ``panel.public_url``.
    # Useful when admins front several bots with different domains
    # behind a single panel install.
    subscription_domain: Mapped[str] = mapped_column(
        String(255), nullable=False, default=""
    )

    # Branding for the HTML subscription page at /page/{token}.
    brand_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    logo_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")
    page_subtitle: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    page_help_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    page_buy_url: Mapped[str] = mapped_column(String(512), nullable=False, default="")

    # Referral / partner programme.
    # ``referral_mode``: ``off`` (default), ``days`` (bonus days credited
    # to the inviter on the invitee's first paid purchase), or
    # ``percent`` (a fraction of every paid order accrues to the
    # inviter's per-currency balance which the admin pays out manually).
    referral_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="off")
    # Up to 3 levels of referral chain. 1 = only direct invites count.
    referral_levels: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    referral_l1_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    referral_l2_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    referral_l3_days: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Percentages stored as integer 0..100 (whole-number percent).
    referral_l1_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    referral_l2_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    referral_l3_percent: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # Free-text instructions shown alongside the partner balance in the
    # bot, e.g. "Напиши /payout — выведу на карту вручную".
    referral_payout_url: Mapped[str] = mapped_column(
        String(512), nullable=False, default=""
    )

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
    plans: Mapped[list["TgBotPlan"]] = relationship(
        back_populates="bot",
        cascade="all, delete-orphan",
        order_by="TgBotPlan.sort_order",
    )
    server_overrides: Mapped[list["BotServerOverride"]] = relationship(
        back_populates="bot",
        cascade="all, delete-orphan",
        lazy="selectin",
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

    # Referral programme: who invited this user (within the same bot)
    # and a stable code other users link with via ``/start ref_<code>``.
    referrer_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("tg_bot_users.id", ondelete="SET NULL"), nullable=True
    )
    referral_code: Mapped[str] = mapped_column(
        String(32), nullable=False, default="", index=True
    )
    referral_first_payment_done: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
    # Per-currency partner balances accrued through the percent-mode
    # referral programme. Admin pays out and resets manually.
    referral_balance_stars: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    referral_balance_usdt_cents: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    referral_balance_rub_kopecks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    referral_total_earned_stars: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    referral_total_earned_usdt_cents: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    referral_total_earned_rub_kopecks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
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


class Plan(Base):
    """A purchasable subscription plan.

    Maps "name + duration" → prices in three currencies. A price of 0
    means the plan is not buyable via that provider. At least one
    non-zero price is required for the plan to be useful. Admins edit
    these in the «💳 Оплата» panel section.
    """

    __tablename__ = "plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    # Admin-facing (never exposed to users); optional data cap applied
    # to the Client row on successful purchase. 0 = unlimited.
    data_limit_bytes: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    # Telegram Stars — integer XTR units; min invoice is 1, max is
    # 2500 (Telegram constraint). 0 = "not sold for stars".
    price_stars: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    # CryptoBot — USDT in cents (100 = $1.00). 0 = not sold via crypto.
    price_crypto_usdt_cents: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )
    # FreeKassa — RUB in kopecks (10000 = ₽100.00). 0 = not sold via
    # FreeKassa.
    price_rub_kopecks: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class Order(Base):
    """One attempted purchase — tracks the invoice across provider webhooks.

    Created the moment a user picks plan + provider in the bot, with
    status ``pending``. The provider returns / POSTs back a payment
    identifier that we match against ``provider_invoice_id``. On
    ``status=paid`` we extend every client of the bot-user and record
    ``applied_at``.
    """

    __tablename__ = "orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # The Telegram bot that initiated the sale (so we can look up
    # credentials / talk back to the user). Nullable for orders made
    # via other channels in the future.
    bot_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("tg_bots.id", ondelete="SET NULL"), nullable=True, index=True
    )
    # The bot user on whose behalf the purchase happens — this is who
    # gets the subscription extension. Nullable so a row survives if
    # the user is deleted.
    bot_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("tg_bot_users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    # Which plan was bought — pinned by id so price edits to the Plan
    # row don't rewrite historical orders. Nullable for manual
    # top-ups in the future.
    plan_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("plans.id", ondelete="SET NULL"), nullable=True
    )
    # Frozen at order-creation time so reporting / refunds see the
    # exact amount the user paid even if the Plan was later edited.
    plan_name: Mapped[str] = mapped_column(
        String(128), nullable=False, default=""
    )
    plan_duration_days: Mapped[int] = mapped_column(
        Integer, nullable=False, default=0
    )

    # ``stars`` | ``cryptobot`` | ``freekassa``
    provider: Mapped[str] = mapped_column(String(32), nullable=False)
    # Currency code used in logs / user-facing text.
    # ``XTR`` | ``USDT`` | ``RUB``
    currency: Mapped[str] = mapped_column(
        String(16), nullable=False, default=""
    )
    # Integer amount in the smallest unit of ``currency``:
    #   XTR → integer stars
    #   USDT → cents (100 = $1.00)
    #   RUB → kopecks (10000 = ₽100.00)
    amount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    # Provider-supplied identifier for the invoice / payload. For
    # Telegram Stars this is the ``invoice_payload`` string we put on
    # ``sendInvoice`` and later read from ``successful_payment``. For
    # CryptoBot it's the ``invoice_id``. For FreeKassa it's the
    # ``MERCHANT_ORDER_ID`` (= ``Order.id``; kept here for symmetry).
    provider_invoice_id: Mapped[str] = mapped_column(
        String(128), nullable=False, default="", index=True
    )
    # Extra provider-specific reference (``pay_url``, ``hash``, ...).
    # Kept as opaque text for the admin UI / audit trail.
    provider_ref: Mapped[str] = mapped_column(
        String(512), nullable=False, default=""
    )

    # ``pending`` → ``paid`` | ``canceled`` | ``expired`` | ``failed``.
    # Terminal statuses are never mutated back to pending.
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default="pending", index=True
    )
    # When the user confirmed the purchase flow (paid status).
    paid_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    # When we applied the extension to the user's clients. ``paid_at``
    # without ``applied_at`` = something blew up mid-extension; admin
    # can retry via «Применить» button.
    applied_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime, nullable=True
    )
    # Free-form reason when terminal status is non-paid.
    notes: Mapped[str] = mapped_column(Text, nullable=False, default="")

    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )


class TgBotPlan(Base):
    """A per-bot subscription plan.

    Lets every bot ship its own price list while the global :class:`Plan`
    table stays as a fallback. ``tg_bots._active_plans`` returns these
    rows (when present) instead of the global ones, so admins can sell
    a 30-day subscription for ₽199 in bot A and for ₽299 in bot B
    without forking the panel.
    """

    __tablename__ = "tg_bot_plans"
    __table_args__ = (
        UniqueConstraint("bot_id", "name", name="uq_tg_bot_plan_name"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bot_id: Mapped[int] = mapped_column(
        ForeignKey("tg_bots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    duration_days: Mapped[int] = mapped_column(Integer, nullable=False)
    data_limit_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_stars: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_crypto_usdt_cents: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    price_rub_kopecks: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    bot: Mapped["TgBot"] = relationship(back_populates="plans")


class BotServerOverride(Base):
    """Per-bot display name override for a server.

    Lets the admin show "🇩🇪 Germany" in bot A's subscription while
    bot B sees the same node as "DE-1". Falls back to ``Server.display_name``
    or ``Server.name`` when no override row exists.
    """

    __tablename__ = "tg_bot_server_overrides"
    __table_args__ = (
        UniqueConstraint("bot_id", "server_id", name="uq_bot_server_override"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bot_id: Mapped[int] = mapped_column(
        ForeignKey("tg_bots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    server_id: Mapped[int] = mapped_column(
        ForeignKey("servers.id", ondelete="CASCADE"), nullable=False, index=True
    )
    display_name: Mapped[str] = mapped_column(String(128), nullable=False, default="")

    bot: Mapped["TgBot"] = relationship(back_populates="server_overrides")


class ReferralAccrual(Base):
    """Audit row for every referral payout event.

    One row per (order, level) when an inviter gets credited under the
    percent-mode programme — also used for ``days``-mode bonuses so the
    bot can show a "history" tab without recomputing from the orders
    table.
    """

    __tablename__ = "referral_accruals"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    bot_id: Mapped[int] = mapped_column(
        ForeignKey("tg_bots.id", ondelete="CASCADE"), nullable=False, index=True
    )
    beneficiary_id: Mapped[int] = mapped_column(
        ForeignKey("tg_bot_users.id", ondelete="CASCADE"),
        nullable=False, index=True,
    )
    source_user_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("tg_bot_users.id", ondelete="SET NULL"), nullable=True
    )
    order_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("orders.id", ondelete="SET NULL"), nullable=True
    )
    # 1, 2 or 3.
    level: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    # Either ``days``, ``stars``, ``usdt_cents`` or ``rub_kopecks`` —
    # mirrors the unit of ``amount``.
    kind: Mapped[str] = mapped_column(String(16), nullable=False)
    amount: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False, index=True
    )

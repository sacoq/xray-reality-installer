"""Pydantic I/O schemas for the panel's JSON API."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------- auth ----------
class LoginIn(BaseModel):
    username: str
    password: str
    # Optional 6-digit TOTP code. Required only when the user has 2FA enabled;
    # the panel answers with 401 {detail: "totp required"} so the UI can prompt.
    totp: Optional[str] = None


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


class TotpSetupOut(BaseModel):
    """Response to ``POST /api/auth/2fa/setup``: a freshly generated TOTP
    secret + a provisioning URI so the browser can render a QR code. The
    secret is *not* persisted until the user verifies a code via
    ``/api/auth/2fa/enable`` — this way a failed enrollment leaves no
    dangling 2FA state on the account."""

    secret: str
    provisioning_uri: str


class TotpVerifyIn(BaseModel):
    secret: str
    code: str = Field(min_length=6, max_length=10)


class TotpDisableIn(BaseModel):
    code: str = Field(min_length=6, max_length=10)


# ---------- audit log ----------
class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int]
    username: str
    action: str
    resource_type: str
    resource_id: str
    details: str
    created_at: datetime


# ---------- telegram notifications ----------
class TelegramConfigIn(BaseModel):
    bot_token: str = ""
    chat_id: str = ""


class TelegramConfigOut(BaseModel):
    bot_token_set: bool
    chat_id: str


# ---------- bulk client ops ----------
class BulkCreateClientsIn(BaseModel):
    # Creates ``count`` clients named ``{email_prefix}-{N}`` starting from 1.
    email_prefix: str = Field(min_length=1, max_length=64)
    count: int = Field(ge=1, le=500)
    label: Optional[str] = None
    flow: str = "xtls-rprx-vision"
    data_limit_bytes: Optional[int] = Field(default=None, ge=0)
    expires_at: Optional[datetime] = None


class BulkExtendClientsIn(BaseModel):
    client_ids: list[int] = Field(default_factory=list, min_length=1)
    extra_days: int = Field(ge=1, le=3650)


class BulkDeleteClientsIn(BaseModel):
    client_ids: list[int] = Field(default_factory=list, min_length=1)


class BulkResultOut(BaseModel):
    affected: int


# ---------- servers ----------
class ServerCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    # Optional human-friendly label used in vless:// link names and every
    # subscription entry. When empty, ``name`` is used. Admins typically
    # set this to something like "🇩🇪 Германия 1" while keeping ``name``
    # as the panel-internal identifier.
    display_name: str = Field(default="", max_length=128)
    agent_url: str
    agent_token: str
    public_host: str
    port: int = 443
    sni: str = "rutube.ru"
    dest: str = "rutube.ru:443"
    # If not provided, the panel will ask the agent to generate an x25519 keypair
    # and a shortId.
    private_key: Optional[str] = None
    public_key: Optional[str] = None
    short_id: Optional[str] = None


class ServerOut(BaseModel):
    id: int
    name: str
    display_name: str = ""
    agent_url: str
    public_host: str
    port: int
    sni: str
    dest: str
    public_key: str
    short_id: str
    created_at: datetime
    online: bool = False
    xray_version: str = ""
    xray_active: bool = False
    client_count: int = 0


class ServerUpdateIn(BaseModel):
    name: Optional[str] = None
    display_name: Optional[str] = Field(default=None, max_length=128)
    agent_url: Optional[str] = None
    agent_token: Optional[str] = None
    public_host: Optional[str] = None
    port: Optional[int] = None
    sni: Optional[str] = None
    dest: Optional[str] = None


# ---------- clients ----------
class ClientCreateIn(BaseModel):
    email: str = Field(min_length=1, max_length=128)
    label: Optional[str] = None
    flow: str = "xtls-rprx-vision"
    # Marzban-style quotas (all optional — None means "no limit").
    data_limit_bytes: Optional[int] = Field(default=None, ge=0)
    expires_at: Optional[datetime] = None


class ClientUpdateIn(BaseModel):
    label: Optional[str] = None
    enabled: Optional[bool] = None
    data_limit_bytes: Optional[int] = Field(default=None, ge=0)
    expires_at: Optional[datetime] = None


class ClientOut(BaseModel):
    id: int
    server_id: int
    uuid: str
    email: str
    label: str
    flow: str
    total_up: int
    total_down: int
    created_at: datetime
    vless_link: str
    enabled: bool = True
    data_limit_bytes: Optional[int] = None
    expires_at: Optional[datetime] = None
    active: bool = True  # derived: enabled AND !expired AND !over-limit
    status: str = "active"  # "active" | "disabled" | "expired" | "limit"


# ---------- enrollments ----------
class EnrollmentCreateIn(BaseModel):
    """Admin-side: create a one-time install token for a new node."""

    name: str = Field(min_length=1, max_length=128)
    public_host: str = ""
    port: int = 443
    sni: str = "rutube.ru"
    dest: str = "rutube.ru:443"
    agent_port: int = 8765


class EnrollmentOut(BaseModel):
    id: int
    token: str
    name: str
    public_host: str
    port: int
    sni: str
    dest: str
    agent_port: int
    agent_token: str
    used_at: Optional[datetime] = None
    server_id: Optional[int] = None
    created_at: datetime
    install_command: str = ""


class EnrollmentDetailsOut(BaseModel):
    """Public response returned to the node's installer when it fetches the
    enrollment by its token. Includes the agent token so the installer can
    write it into the agent env file — the token itself already proves the
    caller knows the enrollment secret."""

    name: str
    port: int
    sni: str
    dest: str
    agent_port: int
    agent_token: str
    public_host: str


class NodeCompleteIn(BaseModel):
    """Installer → panel: 'the agent is up at this URL, please finish setup'.

    SNI/dest/port are optional overrides — set by the installer when it
    auto-probed a better SNI locally than what the admin pre-filled on the
    enrollment (typical case: panel default is ``rutube.ru`` but the node's
    DC can't reach it, so the installer picks ``ya.ru`` and reports back)."""

    agent_url: str
    public_host: Optional[str] = None
    sni: Optional[str] = None
    dest: Optional[str] = None
    port: Optional[int] = None


class NodeCompleteOut(BaseModel):
    ok: bool
    server_id: int
    server_name: str


# ---------- subscriptions ----------
# These fields mirror what the standard Happ / v2rayN / Hiddify subscription
# protocol understands, plus a few xnPanel extras. See models.Subscription
# for what each maps to at the HTTP level.
class SubscriptionCustomisation(BaseModel):
    profile_title: str = Field(default="", max_length=128)
    support_url: str = Field(default="", max_length=255)
    announce: str = Field(default="", max_length=2000)
    provider_id: str = Field(default="", max_length=64)
    routing: str = Field(default="", max_length=8000)
    update_interval_hours: int = Field(default=24, ge=1, le=720)


class SubscriptionCreateIn(SubscriptionCustomisation):
    name: str = Field(min_length=1, max_length=128)
    include_all: bool = True
    client_ids: list[int] = Field(default_factory=list)


class SubscriptionUpdateIn(BaseModel):
    name: Optional[str] = None
    include_all: Optional[bool] = None
    client_ids: Optional[list[int]] = None
    profile_title: Optional[str] = Field(default=None, max_length=128)
    support_url: Optional[str] = Field(default=None, max_length=255)
    announce: Optional[str] = Field(default=None, max_length=2000)
    provider_id: Optional[str] = Field(default=None, max_length=64)
    routing: Optional[str] = Field(default=None, max_length=8000)
    update_interval_hours: Optional[int] = Field(default=None, ge=1, le=720)


class SubscriptionOut(BaseModel):
    id: int
    name: str
    token: str
    include_all: bool
    client_ids: list[int]
    server_ids: list[int]
    item_count: int
    url: str
    profile_title: str = ""
    support_url: str = ""
    announce: str = ""
    provider_id: str = ""
    routing: str = ""
    update_interval_hours: int = 24
    created_at: datetime


# ---------- server management ----------
class XrayLogsOut(BaseModel):
    lines: list[str]


class RebootIn(BaseModel):
    delay_seconds: int = 3


# ---------- api tokens ----------
class ApiTokenCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)


class ApiTokenOut(BaseModel):
    id: int
    name: str
    token: Optional[str] = None  # only set on creation response
    created_at: datetime
    last_used_at: Optional[datetime] = None


# ---------- telegram bots ----------
class TgBotCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    bot_token: str = Field(min_length=10, max_length=128)
    owner_chat_id: str = Field(min_length=1, max_length=64)
    welcome_text: str = ""
    default_server_id: Optional[int] = None
    # When non-empty, /start issues a separate VLESS client per server
    # and the subscription returns one vless:// link per (user, server).
    # Empty = fall back to default_server_id (single-server legacy mode).
    server_ids: list[int] = Field(default_factory=list)
    default_days: int = Field(default=30, ge=0, le=3650)
    default_data_limit_bytes: int = Field(default=0, ge=0)
    device_limit: int = Field(default=3, ge=0, le=100)
    # Subscription customisation applied to every bot-user sub. See
    # SubscriptionCustomisation for semantics. ``profile_title`` supports
    # ``{username}`` and ``{tg_user_id}`` placeholders.
    profile_title: str = Field(default="", max_length=128)
    support_url: str = Field(default="", max_length=255)
    announce: str = Field(default="", max_length=2000)
    provider_id: str = Field(default="", max_length=64)
    routing: str = Field(default="", max_length=8000)
    update_interval_hours: int = Field(default=24, ge=1, le=720)
    enabled: bool = True


class TgBotUpdateIn(BaseModel):
    name: Optional[str] = None
    bot_token: Optional[str] = None
    owner_chat_id: Optional[str] = None
    welcome_text: Optional[str] = None
    default_server_id: Optional[int] = None
    server_ids: Optional[list[int]] = None
    default_days: Optional[int] = Field(default=None, ge=0, le=3650)
    default_data_limit_bytes: Optional[int] = Field(default=None, ge=0)
    device_limit: Optional[int] = Field(default=None, ge=0, le=100)
    profile_title: Optional[str] = Field(default=None, max_length=128)
    support_url: Optional[str] = Field(default=None, max_length=255)
    announce: Optional[str] = Field(default=None, max_length=2000)
    provider_id: Optional[str] = Field(default=None, max_length=64)
    routing: Optional[str] = Field(default=None, max_length=8000)
    update_interval_hours: Optional[int] = Field(default=None, ge=1, le=720)
    enabled: Optional[bool] = None


class TgBotOut(BaseModel):
    id: int
    name: str
    owner_chat_id: str
    welcome_text: str
    default_server_id: Optional[int]
    server_ids: list[int] = Field(default_factory=list)
    default_days: int
    default_data_limit_bytes: int
    device_limit: int
    profile_title: str = ""
    support_url: str = ""
    announce: str = ""
    provider_id: str = ""
    routing: str = ""
    update_interval_hours: int = 24
    enabled: bool
    created_at: datetime
    user_count: int = 0
    running: bool = False


class TgBotUserOut(BaseModel):
    id: int
    bot_id: int
    tg_user_id: str
    tg_username: str
    first_name: str
    sub_token: str
    client_id: Optional[int]
    banned: bool
    created_at: datetime
    device_count_24h: int = 0


class TgBotBanIn(BaseModel):
    banned: bool

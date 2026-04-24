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
    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)


class Server(Base):
    """A managed xray node."""

    __tablename__ = "servers"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False)
    # host/port used to reach the agent (e.g. http://1.2.3.4:8765)
    agent_url: Mapped[str] = mapped_column(String(255), nullable=False)
    agent_token: Mapped[str] = mapped_column(String(255), nullable=False)

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
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )

    clients: Mapped[list["Client"]] = relationship(
        "Client",
        secondary=subscription_clients,
        backref="subscriptions",
    )

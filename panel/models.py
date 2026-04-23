"""DB models for the panel."""
from __future__ import annotations

from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, UniqueConstraint, DateTime, func
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

    created_at: Mapped[datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)

    server: Mapped[Server] = relationship(back_populates="clients")


class Setting(Base):
    """Simple key/value for panel-wide settings."""

    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[str] = mapped_column(Text, nullable=False, default="")

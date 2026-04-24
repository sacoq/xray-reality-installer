"""Pydantic I/O schemas for the panel's JSON API."""
from __future__ import annotations

from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ---------- auth ----------
class LoginIn(BaseModel):
    username: str
    password: str


class ChangePasswordIn(BaseModel):
    current_password: str
    new_password: str = Field(min_length=8)


# ---------- servers ----------
class ServerCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
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
class SubscriptionCreateIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    include_all: bool = True
    client_ids: list[int] = Field(default_factory=list)


class SubscriptionUpdateIn(BaseModel):
    name: Optional[str] = None
    include_all: Optional[bool] = None
    client_ids: Optional[list[int]] = None


class SubscriptionOut(BaseModel):
    id: int
    name: str
    token: str
    include_all: bool
    client_ids: list[int]
    server_ids: list[int]
    item_count: int
    url: str
    created_at: datetime


# ---------- server management ----------
class XrayLogsOut(BaseModel):
    lines: list[str]


class RebootIn(BaseModel):
    delay_seconds: int = 3

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

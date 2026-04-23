"""SQLAlchemy engine / session helpers for the panel."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Generator

from sqlalchemy import create_engine
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


def init_db() -> None:
    # Import models so metadata is populated before create_all.
    from . import models  # noqa: F401

    Base.metadata.create_all(engine)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

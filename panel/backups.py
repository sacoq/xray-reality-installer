"""Encrypted xnPanel backups uploaded to a private GitHub repository.

The panel database contains client credentials, agent tokens and payment/bot
secrets.  Backups therefore never upload a plain SQLite file: a consistent
SQLite snapshot and the small host configuration bundle are compressed and
encrypted with AES-256-GCM before they leave the server.

Non-secret scheduling settings live in the panel ``settings`` table.  The
GitHub token and encryption passphrase are stored separately in a root-only
JSON file so they are not copied into the backup itself.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import os
import re
import secrets
import shutil
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any, Optional

import httpx
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from sqlalchemy.orm import Session

from . import audit as audit_mod
from .database import DB_PATH, SessionLocal


log = logging.getLogger(__name__)

SECRET_FILE = Path(
    os.environ.get(
        "PANEL_BACKUP_SECRET_FILE", "/etc/xray-panel/backup-secrets.json"
    )
)
RESTORE_STAGING_DIR = Path(
    os.environ.get(
        "PANEL_RESTORE_STAGING_DIR", "/var/lib/xray-panel/restore-staging"
    )
)
PANEL_ENV_FILE = Path(
    os.environ.get("PANEL_ENV_FILE", "/etc/xray-panel/panel.env")
)
_OPTIONAL_CONFIG_FILES = (
    PANEL_ENV_FILE,
    Path("/etc/caddy/Caddyfile"),
    Path("/etc/systemd/system/xray-panel.service"),
)

_MAGIC = b"XNPBACKUP1\0"
_SALT_BYTES = 16
_NONCE_BYTES = 12
_PBKDF2_ITERATIONS = 600_000
_GITHUB_API = "https://api.github.com"
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
_RUN_LOCK = threading.Lock()
MAX_IMPORT_BYTES = 90 * 1024 * 1024
MAX_EXTRACTED_DATABASE_BYTES = 1024 * 1024 * 1024


@dataclass(frozen=True)
class BackupSettings:
    enabled: bool = False
    interval_hours: int = 24
    retention_count: int = 14
    github_repo: str = ""
    github_branch: str = "main"
    github_path: str = "xnpanel-backups"
    github_token_set: bool = False
    encryption_password_set: bool = False
    last_attempt_at: str = ""
    last_success_at: str = ""
    last_error: str = ""
    last_github_path: str = ""

    def public_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "interval_hours": self.interval_hours,
            "retention_count": self.retention_count,
            "github_repo": self.github_repo,
            "github_branch": self.github_branch,
            "github_path": self.github_path,
            "github_token_set": self.github_token_set,
            "encryption_password_set": self.encryption_password_set,
            "last_attempt_at": self.last_attempt_at,
            "last_success_at": self.last_success_at,
            "last_error": self.last_error,
            "last_github_path": self.last_github_path,
        }


def _bool_setting(value: str, default: bool = False) -> bool:
    raw = str(value or "").strip().lower()
    if not raw:
        return default
    return raw in {"1", "true", "yes", "on"}


def _int_setting(value: str, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(str(value or "").strip())
    except (TypeError, ValueError):
        return default
    return max(minimum, min(maximum, parsed))


def _load_secrets() -> dict[str, str]:
    try:
        payload = json.loads(SECRET_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("could not read backup secret file: %s", exc)
        return {}
    if not isinstance(payload, dict):
        return {}
    return {
        key: str(payload.get(key) or "")
        for key in ("github_token", "encryption_password")
    }


def _save_secrets(values: dict[str, str]) -> None:
    SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(
        {
            "github_token": str(values.get("github_token") or ""),
            "encryption_password": str(values.get("encryption_password") or ""),
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"
    fd, temporary = tempfile.mkstemp(
        prefix=".backup-secrets-", dir=str(SECRET_FILE.parent)
    )
    tmp = Path(temporary)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(tmp, 0o600)
        os.replace(tmp, SECRET_FILE)
        os.chmod(SECRET_FILE, 0o600)
    finally:
        tmp.unlink(missing_ok=True)


def get_settings(db: Session) -> BackupSettings:
    secret_values = _load_secrets()
    return BackupSettings(
        enabled=_bool_setting(
            audit_mod.setting_get(db, "backup.enabled", "0")
        ),
        interval_hours=_int_setting(
            audit_mod.setting_get(db, "backup.interval_hours", "24"),
            24,
            1,
            720,
        ),
        retention_count=_int_setting(
            audit_mod.setting_get(db, "backup.retention_count", "14"),
            14,
            1,
            100,
        ),
        github_repo=audit_mod.setting_get(db, "backup.github_repo", "").strip(),
        github_branch=(
            audit_mod.setting_get(db, "backup.github_branch", "main").strip()
            or "main"
        ),
        github_path=(
            audit_mod.setting_get(db, "backup.github_path", "xnpanel-backups").strip()
            or "xnpanel-backups"
        ),
        github_token_set=bool(secret_values.get("github_token")),
        encryption_password_set=bool(secret_values.get("encryption_password")),
        last_attempt_at=audit_mod.setting_get(db, "backup.last_attempt_at", ""),
        last_success_at=audit_mod.setting_get(db, "backup.last_success_at", ""),
        last_error=audit_mod.setting_get(db, "backup.last_error", ""),
        last_github_path=audit_mod.setting_get(db, "backup.last_github_path", ""),
    )


def _validate_repo(value: str) -> str:
    cleaned = str(value or "").strip()
    if cleaned and not _REPO_RE.fullmatch(cleaned):
        raise ValueError("GitHub repository must use owner/repository format")
    return cleaned


def _validate_branch(value: str) -> str:
    cleaned = str(value or "").strip() or "main"
    if (
        not _BRANCH_RE.fullmatch(cleaned)
        or ".." in cleaned
        or cleaned.startswith(("/", "."))
        or cleaned.endswith(("/", "."))
    ):
        raise ValueError("invalid GitHub branch")
    return cleaned


def _validate_github_path(value: str) -> str:
    cleaned = str(value or "").strip().strip("/") or "xnpanel-backups"
    path = PurePosixPath(cleaned)
    if len(cleaned) > 240 or any(
        part in {"", ".", ".."}
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", part)
        for part in path.parts
    ):
        raise ValueError("invalid GitHub backup path")
    return str(path)


def update_settings(
    db: Session,
    *,
    enabled: Optional[bool] = None,
    interval_hours: Optional[int] = None,
    retention_count: Optional[int] = None,
    github_repo: Optional[str] = None,
    github_branch: Optional[str] = None,
    github_path: Optional[str] = None,
    github_token: Optional[str] = None,
    encryption_password: Optional[str] = None,
    clear_github_token: bool = False,
    clear_encryption_password: bool = False,
) -> BackupSettings:
    if interval_hours is not None and not 1 <= int(interval_hours) <= 720:
        raise ValueError("backup interval must be between 1 and 720 hours")
    if retention_count is not None and not 1 <= int(retention_count) <= 100:
        raise ValueError("backup retention must be between 1 and 100 files")

    if enabled is not None:
        audit_mod.setting_set(db, "backup.enabled", "1" if enabled else "0")
    if interval_hours is not None:
        audit_mod.setting_set(db, "backup.interval_hours", str(int(interval_hours)))
    if retention_count is not None:
        audit_mod.setting_set(db, "backup.retention_count", str(int(retention_count)))
    if github_repo is not None:
        audit_mod.setting_set(db, "backup.github_repo", _validate_repo(github_repo))
    if github_branch is not None:
        audit_mod.setting_set(db, "backup.github_branch", _validate_branch(github_branch))
    if github_path is not None:
        audit_mod.setting_set(db, "backup.github_path", _validate_github_path(github_path))

    secret_values = _load_secrets()
    if clear_github_token:
        secret_values["github_token"] = ""
    elif github_token is not None and str(github_token).strip():
        secret_values["github_token"] = str(github_token).strip()
    if clear_encryption_password:
        secret_values["encryption_password"] = ""
    elif encryption_password is not None and str(encryption_password):
        if len(str(encryption_password)) < 12:
            raise ValueError("backup encryption password must be at least 12 characters")
        secret_values["encryption_password"] = str(encryption_password)
    if any(
        value is not None
        for value in (github_token, encryption_password)
    ) or clear_github_token or clear_encryption_password:
        _save_secrets(secret_values)

    db.flush()
    settings = get_settings(db)
    if settings.enabled:
        _validate_ready(settings, secret_values)
    return settings


def _validate_ready(
    settings: BackupSettings, secret_values: Optional[dict[str, str]] = None
) -> None:
    secrets_payload = secret_values if secret_values is not None else _load_secrets()
    if not settings.github_repo:
        raise ValueError("GitHub repository is required")
    _validate_repo(settings.github_repo)
    _validate_branch(settings.github_branch)
    _validate_github_path(settings.github_path)
    if not secrets_payload.get("github_token"):
        raise ValueError("GitHub token is required")
    if not secrets_payload.get("encryption_password"):
        raise ValueError("backup encryption password is required")


def _derive_key(password: str, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    ).derive(password.encode("utf-8"))


def encrypt_payload(payload: bytes, password: str) -> bytes:
    """Return a versioned, authenticated encrypted backup payload."""
    if len(password) < 12:
        raise ValueError("backup encryption password must be at least 12 characters")
    salt = secrets.token_bytes(_SALT_BYTES)
    nonce = secrets.token_bytes(_NONCE_BYTES)
    key = _derive_key(password, salt)
    ciphertext = AESGCM(key).encrypt(nonce, payload, _MAGIC)
    return _MAGIC + salt + nonce + ciphertext


def decrypt_payload(payload: bytes, password: str) -> bytes:
    """Decrypt a payload produced by :func:`encrypt_payload` (restore helper)."""
    if not payload.startswith(_MAGIC):
        raise ValueError("not an xnPanel backup")
    offset = len(_MAGIC)
    salt = payload[offset : offset + _SALT_BYTES]
    offset += _SALT_BYTES
    nonce = payload[offset : offset + _NONCE_BYTES]
    offset += _NONCE_BYTES
    if len(salt) != _SALT_BYTES or len(nonce) != _NONCE_BYTES:
        raise ValueError("truncated xnPanel backup")
    return AESGCM(_derive_key(password, salt)).decrypt(
        nonce, payload[offset:], _MAGIC
    )


def _sqlite_snapshot(destination: Path) -> None:
    if not DB_PATH.exists():
        raise FileNotFoundError(f"panel database is missing: {DB_PATH}")
    source = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True, timeout=30)
    target = sqlite3.connect(str(destination), timeout=30)
    try:
        source.backup(target)
        row = target.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise RuntimeError(f"SQLite backup integrity check failed: {row}")
    finally:
        target.close()
        source.close()


def _archive_payload(created_at: datetime) -> bytes:
    with tempfile.TemporaryDirectory(prefix="xnpanel-backup-") as directory:
        root = Path(directory)
        database_copy = root / "panel.db"
        _sqlite_snapshot(database_copy)
        manifest = {
            "format": 1,
            "created_at": created_at.isoformat(),
            "hostname": socket.gethostname(),
            "database": "panel.db",
            "database_sha256": hashlib.sha256(database_copy.read_bytes()).hexdigest(),
            "config_files": [],
            "restore_note": (
                "Decrypt first, extract the tar.gz, stop xray-panel, replace "
                "the database and configuration files, then restart the service."
            ),
        }
        archive = BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as tar:
            tar.add(database_copy, arcname="panel.db", recursive=False)
            for config_path in _OPTIONAL_CONFIG_FILES:
                try:
                    if not config_path.is_file() or config_path.is_symlink():
                        continue
                    data = config_path.read_bytes()
                except OSError:
                    continue
                arcname = f"config/{config_path.as_posix().lstrip('/')}"
                info = tarfile.TarInfo(arcname)
                info.size = len(data)
                info.mode = 0o600
                info.mtime = int(created_at.timestamp())
                tar.addfile(info, BytesIO(data))
                manifest["config_files"].append(
                    {
                        "source": str(config_path),
                        "archive": arcname,
                        "sha256": hashlib.sha256(data).hexdigest(),
                    }
                )
            manifest_bytes = json.dumps(
                manifest, ensure_ascii=False, indent=2, sort_keys=True
            ).encode("utf-8") + b"\n"
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_bytes)
            info.mode = 0o600
            info.mtime = int(created_at.timestamp())
            tar.addfile(info, BytesIO(manifest_bytes))
        return archive.getvalue()


def export_backup() -> tuple[bytes, str, str]:
    """Create one encrypted download without contacting GitHub."""
    now = datetime.now(timezone.utc)
    secret_values = _load_secrets()
    password = secret_values.get("encryption_password", "")
    if not password:
        raise ValueError("backup encryption password is required")
    encrypted = encrypt_payload(_archive_payload(now), password)
    if len(encrypted) > MAX_IMPORT_BYTES:
        raise RuntimeError("encrypted backup is too large for browser export")
    filename = now.strftime("xnpanel-%Y%m%dT%H%M%S-%fZ.xnpbackup")
    return encrypted, filename, now.isoformat()


def _safe_tar_members(archive: tarfile.TarFile) -> list[tarfile.TarInfo]:
    allowed = {"panel.db", "manifest.json"}
    members: list[tarfile.TarInfo] = []
    total_size = 0
    for member in archive.getmembers():
        pure = PurePosixPath(member.name)
        if (
            member.islnk()
            or member.issym()
            or member.isdir()
            or pure.is_absolute()
            or ".." in pure.parts
        ):
            raise ValueError(f"unsafe backup member: {member.name}")
        if member.name not in allowed and not member.name.startswith("config/"):
            raise ValueError(f"unexpected backup member: {member.name}")
        total_size += max(0, int(member.size or 0))
        if total_size > MAX_EXTRACTED_DATABASE_BYTES + 16 * 1024 * 1024:
            raise ValueError("backup expands beyond the permitted size")
        members.append(member)
    names = {member.name for member in members}
    if not allowed.issubset(names):
        raise ValueError("backup must contain panel.db and manifest.json")
    return members


def _validate_staged_database(path: Path, expected_sha256: str = "") -> None:
    if not path.is_file():
        raise ValueError("backup database is missing")
    if path.stat().st_size > MAX_EXTRACTED_DATABASE_BYTES:
        raise ValueError("backup database is too large")
    if expected_sha256:
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if not secrets.compare_digest(actual, expected_sha256.lower()):
            raise ValueError("backup database checksum does not match manifest")
    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True, timeout=30)
    try:
        row = connection.execute("PRAGMA integrity_check").fetchone()
        if not row or str(row[0]).lower() != "ok":
            raise ValueError(f"backup SQLite integrity check failed: {row}")
        tables = {
            str(value[0])
            for value in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        required = {"users", "servers", "clients", "settings"}
        if not required.issubset(tables):
            raise ValueError("backup database is not an xnPanel database")
    finally:
        connection.close()


def _cleanup_expired_staging(*, now: Optional[datetime] = None) -> None:
    current = now or datetime.now(timezone.utc)
    try:
        rows = list(RESTORE_STAGING_DIR.iterdir())
    except FileNotFoundError:
        return
    for row in rows:
        if not row.is_dir() or row.is_symlink():
            continue
        try:
            metadata = json.loads((row / "staged.json").read_text(encoding="utf-8"))
            expires = _parse_datetime(str(metadata.get("expires_at") or ""))
        except (OSError, ValueError, json.JSONDecodeError):
            expires = datetime.fromtimestamp(row.stat().st_mtime, tz=timezone.utc) + timedelta(hours=1)
        if expires is not None and expires <= current:
            shutil.rmtree(row, ignore_errors=True)


def stage_import(payload: bytes, password: str) -> dict[str, Any]:
    """Decrypt, inspect and stage a browser-uploaded backup for confirmation."""
    if not payload or len(payload) > MAX_IMPORT_BYTES:
        raise ValueError("backup file is empty or too large")
    if len(str(password or "")) < 12:
        raise ValueError("backup encryption password must be at least 12 characters")
    try:
        archive_bytes = decrypt_payload(payload, str(password))
    except Exception as exc:
        raise ValueError("could not decrypt backup; check the password and file") from exc
    restore_id = secrets.token_urlsafe(18)
    RESTORE_STAGING_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(RESTORE_STAGING_DIR, 0o700)
    _cleanup_expired_staging()
    stage = RESTORE_STAGING_DIR / restore_id
    stage.mkdir(mode=0o700)
    try:
        with tarfile.open(fileobj=BytesIO(archive_bytes), mode="r:gz") as archive:
            members = _safe_tar_members(archive)
            for member in members:
                target = stage.joinpath(*PurePosixPath(member.name).parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"could not read backup member {member.name}")
                with target.open("wb") as output:
                    shutil.copyfileobj(source, output, length=1024 * 1024)
                os.chmod(target, 0o600)
        manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
        if not isinstance(manifest, dict) or int(manifest.get("format") or 0) != 1:
            raise ValueError("unsupported xnPanel backup format")
        _validate_staged_database(
            stage / "panel.db", str(manifest.get("database_sha256") or "")
        )
        created_at = str(manifest.get("created_at") or "")
        expires_at = datetime.now(timezone.utc) + timedelta(minutes=30)
        metadata = {
            "restore_id": restore_id,
            "created_at": created_at,
            "hostname": str(manifest.get("hostname") or ""),
            "database_bytes": (stage / "panel.db").stat().st_size,
            "config_files": manifest.get("config_files") or [],
            "expires_at": expires_at.isoformat(),
        }
        (stage / "staged.json").write_text(
            json.dumps(metadata, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(stage / "staged.json", 0o600)
        return metadata
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _validated_stage(restore_id: str) -> tuple[Path, dict[str, Any]]:
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,64}", str(restore_id or "")):
        raise ValueError("invalid restore id")
    base = RESTORE_STAGING_DIR.resolve()
    stage = (RESTORE_STAGING_DIR / restore_id).resolve()
    if base not in stage.parents or not stage.is_dir():
        raise ValueError("staged restore not found")
    try:
        metadata = json.loads((stage / "staged.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("staged restore metadata is unavailable") from exc
    expires = _parse_datetime(str(metadata.get("expires_at") or ""))
    if expires is None or expires <= datetime.now(timezone.utc):
        shutil.rmtree(stage, ignore_errors=True)
        raise ValueError("staged restore expired; upload the backup again")
    _validate_staged_database(stage / "panel.db")
    return stage, metadata


def schedule_import(restore_id: str, *, confirmation: str) -> dict[str, Any]:
    """Schedule a detached restore so the HTTP response can finish first."""
    if str(confirmation or "").strip() != "ВОССТАНОВИТЬ":
        raise ValueError("type ВОССТАНОВИТЬ to confirm the restore")
    stage, metadata = _validated_stage(restore_id)
    unit = f"xnpanel-restore-{restore_id[:12].lower()}"
    command = [
        "systemd-run",
        f"--unit={unit}",
        "--on-active=3s",
        "--collect",
        sys.executable,
        "-m",
        "panel.restore_helper",
        "--stage",
        str(stage),
    ]
    result = subprocess.run(command, capture_output=True, text=True, timeout=20)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemd-run failed").strip()
        raise RuntimeError(detail[-2000:])
    return {
        "ok": True,
        "restore_id": restore_id,
        "scheduled": True,
        "restart_in_seconds": 3,
        "backup_created_at": metadata.get("created_at", ""),
    }


def _github_headers(token: str) -> dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "xnPanel-backup/1.0",
    }


def _github_error(response: httpx.Response) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    message = str(payload.get("message") or response.reason_phrase or "GitHub error")
    return f"GitHub HTTP {response.status_code}: {message}"[:1000]


def _verify_private_repository(
    client: httpx.Client, *, repo: str, headers: dict[str, str]
) -> None:
    response = client.get(f"{_GITHUB_API}/repos/{repo}", headers=headers)
    if response.status_code != 200:
        raise RuntimeError(_github_error(response))
    payload = response.json()
    if not bool(payload.get("private")):
        raise RuntimeError("refusing to upload a panel backup to a public repository")


def _delete_old_backups(
    client: httpx.Client,
    *,
    repo: str,
    branch: str,
    directory: str,
    keep: int,
    headers: dict[str, str],
) -> int:
    response = client.get(
        f"{_GITHUB_API}/repos/{repo}/contents/{directory}",
        headers=headers,
        params={"ref": branch},
    )
    if response.status_code == 404:
        return 0
    if response.status_code != 200:
        raise RuntimeError(_github_error(response))
    rows = response.json()
    if not isinstance(rows, list):
        return 0
    candidates = sorted(
        (
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("name") or "").endswith(".xnpbackup")
            and row.get("sha")
        ),
        key=lambda row: str(row.get("name") or ""),
        reverse=True,
    )
    deleted = 0
    for row in candidates[max(1, keep) :]:
        path = str(row.get("path") or "")
        if not path:
            continue
        delete_response = client.request(
            "DELETE",
            f"{_GITHUB_API}/repos/{repo}/contents/{path}",
            headers=headers,
            json={
                "message": f"xnPanel backup retention: remove {row.get('name')}",
                "sha": row["sha"],
                "branch": branch,
            },
        )
        if delete_response.status_code not in {200, 204}:
            raise RuntimeError(_github_error(delete_response))
        deleted += 1
    return deleted


def _existing_backup_rows(
    client: httpx.Client,
    *,
    repo: str,
    branch: str,
    directory: str,
    headers: dict[str, str],
) -> list[dict[str, Any]]:
    response = client.get(
        f"{_GITHUB_API}/repos/{repo}/contents/{directory}",
        headers=headers,
        params={"ref": branch},
    )
    if response.status_code == 404:
        return []
    if response.status_code != 200:
        raise RuntimeError(_github_error(response))
    rows = response.json()
    if not isinstance(rows, list):
        return []
    return sorted(
        (
            row
            for row in rows
            if isinstance(row, dict)
            and str(row.get("name") or "").endswith(".xnpbackup")
            and row.get("path")
        ),
        key=lambda row: str(row.get("name") or ""),
        reverse=True,
    )


def _upload_large_backup_via_git_database(
    client: httpx.Client,
    *,
    settings: BackupSettings,
    headers: dict[str, str],
    encrypted: bytes,
    path: str,
    created_at: datetime,
) -> int:
    """Commit one large backup without the Contents API size ceiling.

    GitHub's Contents endpoint may reject JSON/base64 requests well below the
    repository's 100 MiB blob limit.  The Git Database API stores the same
    single file through a blob/tree/commit transaction.  Retention deletions
    are included in that one commit, so a failed ref update never leaves the
    branch in a partially updated state.
    """
    blob_response = client.post(
        f"{_GITHUB_API}/repos/{settings.github_repo}/git/blobs",
        headers=headers,
        json={
            "content": base64.b64encode(encrypted).decode("ascii"),
            "encoding": "base64",
        },
    )
    if blob_response.status_code != 201:
        raise RuntimeError(_github_error(blob_response))
    blob_sha = str(blob_response.json().get("sha") or "")
    if not re.fullmatch(r"[0-9a-f]{40}", blob_sha):
        raise RuntimeError("GitHub returned an invalid backup blob SHA")

    directory = str(PurePosixPath(path).parent)
    existing = _existing_backup_rows(
        client,
        repo=settings.github_repo,
        branch=settings.github_branch,
        directory=directory,
        headers=headers,
    )
    # The just-created filename sorts newest, so retain at most keep-1 old
    # rows and delete the remainder in the same tree transaction.
    delete_rows = existing[max(0, settings.retention_count - 1) :]

    # A concurrent commit to the configured branch is possible. Rebuild from
    # the new head a bounded number of times instead of forcing the ref.
    for attempt in range(3):
        ref_response = client.get(
            f"{_GITHUB_API}/repos/{settings.github_repo}/git/ref/heads/"
            f"{settings.github_branch}",
            headers=headers,
        )
        if ref_response.status_code != 200:
            raise RuntimeError(_github_error(ref_response))
        parent_sha = str(
            (ref_response.json().get("object") or {}).get("sha") or ""
        )
        commit_response = client.get(
            f"{_GITHUB_API}/repos/{settings.github_repo}/git/commits/{parent_sha}",
            headers=headers,
        )
        if commit_response.status_code != 200:
            raise RuntimeError(_github_error(commit_response))
        base_tree = str(
            (commit_response.json().get("tree") or {}).get("sha") or ""
        )
        tree_entries: list[dict[str, Any]] = [
            {
                "path": path,
                "mode": "100644",
                "type": "blob",
                "sha": blob_sha,
            }
        ]
        tree_entries.extend(
            {
                "path": str(row.get("path") or ""),
                "mode": "100644",
                "type": "blob",
                "sha": None,
            }
            for row in delete_rows
            if str(row.get("path") or "") != path
        )
        tree_response = client.post(
            f"{_GITHUB_API}/repos/{settings.github_repo}/git/trees",
            headers=headers,
            json={"base_tree": base_tree, "tree": tree_entries},
        )
        if tree_response.status_code != 201:
            raise RuntimeError(_github_error(tree_response))
        tree_sha = str(tree_response.json().get("sha") or "")
        new_commit_response = client.post(
            f"{_GITHUB_API}/repos/{settings.github_repo}/git/commits",
            headers=headers,
            json={
                "message": f"xnPanel encrypted backup {created_at.isoformat()}",
                "tree": tree_sha,
                "parents": [parent_sha],
            },
        )
        if new_commit_response.status_code != 201:
            raise RuntimeError(_github_error(new_commit_response))
        new_commit_sha = str(new_commit_response.json().get("sha") or "")
        update_response = client.patch(
            f"{_GITHUB_API}/repos/{settings.github_repo}/git/refs/heads/"
            f"{settings.github_branch}",
            headers=headers,
            json={"sha": new_commit_sha, "force": False},
        )
        if update_response.status_code == 200:
            return len(delete_rows)
        if update_response.status_code != 422 or attempt == 2:
            raise RuntimeError(_github_error(update_response))
    raise RuntimeError("GitHub branch changed while committing the backup")


def _upload_to_github(
    *,
    settings: BackupSettings,
    token: str,
    encrypted: bytes,
    created_at: datetime,
) -> tuple[str, int]:
    max_bytes = 90 * 1024 * 1024
    if len(encrypted) > max_bytes:
        raise RuntimeError(
            f"encrypted backup is {len(encrypted)} bytes; GitHub limit is {max_bytes}"
        )
    host = re.sub(r"[^A-Za-z0-9_.-]+", "-", socket.gethostname()).strip("-.")
    host = host or "panel"
    directory = f"{settings.github_path}/{host}"
    filename = created_at.strftime("xnpanel-%Y%m%dT%H%M%S-%fZ.xnpbackup")
    path = f"{directory}/{filename}"
    headers = _github_headers(token)
    with httpx.Client(timeout=90.0, follow_redirects=False) as client:
        _verify_private_repository(client, repo=settings.github_repo, headers=headers)
        if len(encrypted) > 10 * 1024 * 1024:
            deleted = _upload_large_backup_via_git_database(
                client,
                settings=settings,
                headers=headers,
                encrypted=encrypted,
                path=path,
                created_at=created_at,
            )
        else:
            response = client.put(
                f"{_GITHUB_API}/repos/{settings.github_repo}/contents/{path}",
                headers=headers,
                json={
                    "message": f"xnPanel encrypted backup {created_at.isoformat()}",
                    "content": base64.b64encode(encrypted).decode("ascii"),
                    "branch": settings.github_branch,
                },
            )
            if response.status_code not in {200, 201}:
                raise RuntimeError(_github_error(response))
            deleted = _delete_old_backups(
                client,
                repo=settings.github_repo,
                branch=settings.github_branch,
                directory=directory,
                keep=settings.retention_count,
                headers=headers,
            )
    return path, deleted


def _safe_error(exc: Exception) -> str:
    text = f"{type(exc).__name__}: {exc}".replace("\r", " ").replace("\n", " ")
    return text[:2000]


def run_backup(*, trigger: str = "manual") -> dict[str, Any]:
    """Create, encrypt and upload one backup.

    A process-wide lock prevents a manual click and the scheduler from
    generating two large encrypted blobs at the same time.
    """
    if not _RUN_LOCK.acquire(blocking=False):
        raise RuntimeError("another backup is already running")
    now = datetime.now(timezone.utc)
    try:
        with SessionLocal() as db:
            settings = get_settings(db)
            secret_values = _load_secrets()
            _validate_ready(settings, secret_values)
            audit_mod.setting_set(db, "backup.last_attempt_at", now.isoformat())
            audit_mod.setting_set(db, "backup.last_error", "")
            db.commit()
        archive = _archive_payload(now)
        encrypted = encrypt_payload(
            archive, secret_values["encryption_password"]
        )
        path, deleted = _upload_to_github(
            settings=settings,
            token=secret_values["github_token"],
            encrypted=encrypted,
            created_at=now,
        )
        with SessionLocal() as db:
            audit_mod.setting_set(db, "backup.last_success_at", now.isoformat())
            audit_mod.setting_set(db, "backup.last_github_path", path)
            audit_mod.setting_set(db, "backup.last_error", "")
            audit_mod.record(
                db,
                user=None,
                action="backup.success",
                resource_type="backup",
                resource_id=path,
                details=f"trigger={trigger}; bytes={len(encrypted)}; deleted={deleted}",
            )
            db.commit()
        return {
            "ok": True,
            "github_path": path,
            "created_at": now.isoformat(),
            "size_bytes": len(encrypted),
            "deleted_old_backups": deleted,
        }
    except Exception as exc:
        error = _safe_error(exc)
        try:
            with SessionLocal() as db:
                audit_mod.setting_set(db, "backup.last_attempt_at", now.isoformat())
                audit_mod.setting_set(db, "backup.last_error", error)
                audit_mod.record(
                    db,
                    user=None,
                    action="backup.failed",
                    resource_type="backup",
                    details=f"trigger={trigger}; {error}",
                    notify=True,
                )
                db.commit()
        except Exception:  # noqa: BLE001
            log.exception("could not persist backup failure")
        raise
    finally:
        _RUN_LOCK.release()


def _parse_datetime(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def backup_due(settings: BackupSettings, *, now: Optional[datetime] = None) -> bool:
    if not settings.enabled:
        return False
    current = now or datetime.now(timezone.utc)
    last_attempt = _parse_datetime(settings.last_attempt_at)
    return last_attempt is None or current >= last_attempt + timedelta(
        hours=settings.interval_hours
    )


class BackupManager:
    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if self._task is not None and not self._task.done():
            return
        self._stopping.clear()
        self._task = asyncio.create_task(self._loop(), name="github-backup")
        log.info("GitHub backup scheduler started")

    async def stop(self) -> None:
        self._stopping.set()
        if self._task is not None and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        self._task = None

    async def _loop(self) -> None:
        try:
            await asyncio.wait_for(self._stopping.wait(), timeout=20)
            return
        except asyncio.TimeoutError:
            pass
        while not self._stopping.is_set():
            try:
                with SessionLocal() as db:
                    settings = get_settings(db)
                if backup_due(settings):
                    await asyncio.to_thread(run_backup, trigger="scheduled")
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled GitHub backup failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass


manager = BackupManager()


__all__ = [
    "BackupSettings",
    "backup_due",
    "decrypt_payload",
    "encrypt_payload",
    "export_backup",
    "get_settings",
    "manager",
    "run_backup",
    "schedule_import",
    "stage_import",
    "update_settings",
]

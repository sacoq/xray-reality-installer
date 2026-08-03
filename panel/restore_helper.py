"""Detached, rollback-safe xnPanel restore helper.

The web process schedules this module with ``systemd-run`` after returning a
successful confirmation response.  Running in a separate transient unit lets
the helper stop xray-panel, replace SQLite/config files without open panel DB
connections, and start the service again.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from .backups import (
    RESTORE_STAGING_DIR,
    _OPTIONAL_CONFIG_FILES,
    _validate_staged_database,
)
from .database import DB_PATH


ROLLBACK_DIR = Path(
    os.environ.get(
        "PANEL_RESTORE_ROLLBACK_DIR", "/var/lib/xray-panel/restore-rollbacks"
    )
)
PANEL_SERVICE = os.environ.get("PANEL_SERVICE", "xray-panel.service")


def _systemctl(action: str, *, check: bool = True) -> None:
    result = subprocess.run(
        ["systemctl", action, PANEL_SERVICE],
        capture_output=True,
        text=True,
        timeout=60,
    )
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "systemctl failed").strip()
        raise RuntimeError(f"systemctl {action} failed: {detail[-2000:]}")


def _copy_atomic(source: Path, destination: Path, *, mode: int = 0o600) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".restore-tmp")
    shutil.copy2(source, temporary)
    os.chmod(temporary, mode)
    os.replace(temporary, destination)


def _backup_current(rollback: Path) -> dict[str, str]:
    rollback.mkdir(parents=True, mode=0o700)
    copied: dict[str, str] = {}
    if DB_PATH.is_file():
        target = rollback / "panel.db"
        shutil.copy2(DB_PATH, target)
        os.chmod(target, 0o600)
        copied[str(DB_PATH)] = str(target)
    for source in _OPTIONAL_CONFIG_FILES:
        if not source.is_file() or source.is_symlink():
            continue
        target = rollback / "config" / source.as_posix().lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        os.chmod(target, 0o600)
        copied[str(source)] = str(target)
    (rollback / "files.json").write_text(
        json.dumps(copied, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return copied


def _restore_files(stage: Path, manifest: dict) -> None:
    _validate_staged_database(stage / "panel.db")
    _copy_atomic(stage / "panel.db", DB_PATH)
    allowed = {str(path): path for path in _OPTIONAL_CONFIG_FILES}
    for row in manifest.get("config_files") or []:
        if not isinstance(row, dict):
            continue
        destination = allowed.get(str(row.get("source") or ""))
        archive_name = str(row.get("archive") or "")
        if destination is None or not archive_name.startswith("config/"):
            continue
        source = stage.joinpath(*Path(archive_name).parts)
        if source.is_file() and not source.is_symlink():
            _copy_atomic(source, destination)


def _rollback_files(copied: dict[str, str]) -> None:
    for destination_raw, source_raw in copied.items():
        source = Path(source_raw)
        destination = Path(destination_raw)
        if source.is_file():
            _copy_atomic(source, destination)


def _prune_rollbacks(keep: int = 3) -> None:
    try:
        rows = sorted(
            (row for row in ROLLBACK_DIR.iterdir() if row.is_dir()),
            key=lambda row: row.name,
            reverse=True,
        )
    except FileNotFoundError:
        return
    for row in rows[max(1, keep) :]:
        shutil.rmtree(row, ignore_errors=True)


def restore(stage: Path) -> None:
    stage = stage.resolve()
    staging_root = RESTORE_STAGING_DIR.resolve()
    if staging_root not in stage.parents or not stage.is_dir() or stage.is_symlink():
        raise ValueError("restore stage must be inside the panel staging directory")
    manifest = json.loads((stage / "manifest.json").read_text(encoding="utf-8"))
    _validate_staged_database(
        stage / "panel.db", str(manifest.get("database_sha256") or "")
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    rollback = ROLLBACK_DIR / stamp
    ROLLBACK_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(ROLLBACK_DIR, 0o700)
    copied = _backup_current(rollback)
    stopped = False
    try:
        _systemctl("stop")
        stopped = True
        _restore_files(stage, manifest)
        _systemctl("start")
        stopped = False
        shutil.rmtree(stage, ignore_errors=True)
        _prune_rollbacks()
    except Exception:
        if stopped:
            try:
                _rollback_files(copied)
            finally:
                _systemctl("start", check=False)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--stage", required=True)
    args = parser.parse_args()
    restore(Path(args.stage))


if __name__ == "__main__":
    main()

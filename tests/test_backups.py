from __future__ import annotations

import unittest
import sqlite3
import tempfile
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from cryptography.exceptions import InvalidTag

from panel import backups
from panel.backups import BackupSettings, backup_due, decrypt_payload, encrypt_payload


class _Response:
    def __init__(self, status_code: int, payload: object):
        self.status_code = status_code
        self._payload = payload
        self.reason_phrase = "test"

    def json(self) -> object:
        return self._payload


class _GitDatabaseClient:
    def __init__(self) -> None:
        self.tree_payload: dict[str, object] = {}

    def get(self, url: str, **_: object) -> _Response:
        if "/contents/" in url:
            return _Response(
                200,
                [
                    {
                        "name": "xnpanel-20260802T000000Z.xnpbackup",
                        "path": "xnpanel-backups/host/xnpanel-20260802T000000Z.xnpbackup",
                    },
                    {
                        "name": "xnpanel-20260801T000000Z.xnpbackup",
                        "path": "xnpanel-backups/host/xnpanel-20260801T000000Z.xnpbackup",
                    },
                ],
            )
        if "/git/ref/heads/" in url:
            return _Response(200, {"object": {"sha": "b" * 40}})
        if "/git/commits/" in url:
            return _Response(200, {"tree": {"sha": "c" * 40}})
        raise AssertionError(url)

    def post(self, url: str, *, json: dict[str, object], **_: object) -> _Response:
        if url.endswith("/git/blobs"):
            return _Response(201, {"sha": "a" * 40})
        if url.endswith("/git/trees"):
            self.tree_payload = json
            return _Response(201, {"sha": "d" * 40})
        if url.endswith("/git/commits"):
            return _Response(201, {"sha": "e" * 40})
        raise AssertionError(url)

    def patch(self, url: str, **_: object) -> _Response:
        if "/git/refs/heads/" not in url:
            raise AssertionError(url)
        return _Response(200, {"object": {"sha": "e" * 40}})


class BackupCryptoTests(unittest.TestCase):
    def test_encrypted_backup_round_trip(self) -> None:
        payload = b"sqlite and configuration payload\x00" * 100
        encrypted = encrypt_payload(payload, "correct horse battery staple")
        self.assertNotIn(payload[:30], encrypted)
        self.assertEqual(
            decrypt_payload(encrypted, "correct horse battery staple"), payload
        )

    def test_wrong_password_is_rejected(self) -> None:
        encrypted = encrypt_payload(b"secret", "correct horse battery staple")
        with self.assertRaises(InvalidTag):
            decrypt_payload(encrypted, "this password is definitely wrong")


class BackupScheduleTests(unittest.TestCase):
    def test_disabled_backup_is_never_due(self) -> None:
        self.assertFalse(backup_due(BackupSettings(enabled=False)))

    def test_due_uses_last_attempt_to_avoid_failure_storms(self) -> None:
        now = datetime(2026, 8, 3, tzinfo=timezone.utc)
        recent = BackupSettings(
            enabled=True,
            interval_hours=24,
            last_attempt_at=(now - timedelta(hours=1)).isoformat(),
        )
        old = BackupSettings(
            enabled=True,
            interval_hours=24,
            last_attempt_at=(now - timedelta(hours=25)).isoformat(),
        )
        self.assertFalse(backup_due(recent, now=now))
        self.assertTrue(backup_due(old, now=now))


class BackupGitDatabaseTests(unittest.TestCase):
    def test_large_backup_is_one_blob_with_atomic_retention(self) -> None:
        client = _GitDatabaseClient()
        settings = BackupSettings(
            github_repo="owner/private",
            github_branch="main",
            retention_count=2,
        )
        new_path = "xnpanel-backups/host/xnpanel-20260803T000000Z.xnpbackup"

        deleted = backups._upload_large_backup_via_git_database(
            client,  # type: ignore[arg-type]
            settings=settings,
            headers={},
            encrypted=b"encrypted",
            path=new_path,
            created_at=datetime(2026, 8, 3, tzinfo=timezone.utc),
        )

        self.assertEqual(deleted, 1)
        entries = client.tree_payload["tree"]
        self.assertIsInstance(entries, list)
        self.assertEqual(entries[0]["path"], new_path)  # type: ignore[index]
        self.assertEqual(entries[0]["sha"], "a" * 40)  # type: ignore[index]
        self.assertEqual(entries[1]["sha"], None)  # type: ignore[index]
        self.assertIn("20260801", entries[1]["path"])  # type: ignore[index]


class BackupImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.database = self.root / "panel.db"
        with closing(sqlite3.connect(self.database)) as connection:
            for table in ("users", "servers", "clients", "settings"):
                connection.execute(
                    f'CREATE TABLE "{table}" (id INTEGER PRIMARY KEY, value TEXT)'
                )
            connection.execute(
                "INSERT INTO settings (value) VALUES (?)", ("round-trip",)
            )
            connection.commit()
        self.config = self.root / "panel.env"
        self.config.write_text("PANEL_SECRET=test\n", encoding="utf-8")
        self.staging = self.root / "staging"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_export_archive_can_be_staged_and_validated(self) -> None:
        password = "a sufficiently long test password"
        created_at = datetime(2026, 8, 3, tzinfo=timezone.utc)
        with (
            patch.object(backups, "DB_PATH", self.database),
            patch.object(backups, "RESTORE_STAGING_DIR", self.staging),
            patch.object(backups, "_OPTIONAL_CONFIG_FILES", (self.config,)),
        ):
            encrypted = backups.encrypt_payload(
                backups._archive_payload(created_at), password
            )
            preview = backups.stage_import(encrypted, password)

        stage = self.staging / preview["restore_id"]
        self.assertTrue((stage / "panel.db").is_file())
        self.assertEqual(preview["created_at"], created_at.isoformat())
        self.assertEqual(len(preview["config_files"]), 1)
        with closing(sqlite3.connect(stage / "panel.db")) as connection:
            self.assertEqual(
                connection.execute("SELECT value FROM settings").fetchone()[0],
                "round-trip",
            )

    def test_stage_rejects_wrong_password_without_leaving_files(self) -> None:
        encrypted = backups.encrypt_payload(b"not-an-archive", "correct password")
        with patch.object(backups, "RESTORE_STAGING_DIR", self.staging):
            with self.assertRaisesRegex(ValueError, "could not decrypt"):
                backups.stage_import(encrypted, "different password")
        self.assertFalse(self.staging.exists())


if __name__ == "__main__":
    unittest.main()

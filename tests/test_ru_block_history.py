from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

from agent import ru_block_history
from agent.ru_block_history import History, read_history


def row(dest, outbound="panel-ru-destination-block", minute="01"):
    return (
        f"2026/10/23 01:{minute}:01.000 from 192.0.2.9:3746 accepted tcp:{dest} "
        f"[vless -> {outbound}] email: private-id\n"
    ).encode()


class BlockHistoryTests(unittest.TestCase):
    def setUp(self):
        work = TemporaryDirectory()
        self.addCleanup(work.cleanup)
        self.log = Path(work.name, "samples.log")
        self.db = Path(work.name, "history.sqlite3")

    def test_records_only_aggregate_block_destinations(self):
        self.log.write_bytes(
            row("Example.org:443") + row("95.129.232.180:443") +
            row("[2a02:6b8::2]:443") + row("192.0.2.5:443") +
            row("direct.example.org:443", "direct")
        )
        with History(self.db, self.log, "boot-1") as store:
            store.collect()
            store.collect()
        report = read_history(self.db)
        self.assertEqual(report["domains"], {"example.org": 1})
        self.assertEqual(report["ip_destinations"], {"95.129.232.180": 1, "2a02:6b8::2": 1})
        self.assertEqual(report["unidentified"], 1)
        self.assertEqual(report["total_hits"], 4)
        contents = self.db.read_bytes()
        for private in (b"192.0.2.9", b"192.0.2.5", b"private-id", b"direct.example.org"):
            self.assertNotIn(private, contents)

    def test_replacement_and_restart_keep_previous_counts(self):
        self.log.write_bytes(row("a.example.org:443"))
        with History(self.db, self.log, "boot-1") as store:
            store.collect()
        self.log.write_bytes(row("b.example.org:443", minute="02") * 3)
        with History(self.db, self.log, "boot-1") as store:
            store.collect()
        with History(self.db, self.log, "boot-1") as store:
            store.collect()
        self.assertEqual(read_history(self.db)["domains"], {"a.example.org": 1, "b.example.org": 3})

    def test_bounded_response_counts_every_row(self):
        self.log.write_bytes(row("a.example.org:443") + row("b.example.org:443") * 2)
        with History(self.db, self.log, "boot-1") as store:
            store.collect()
        report = read_history(self.db, limit=1)
        self.assertEqual(report["total_hits"], 3)
        self.assertTrue(report["truncated"])
        self.assertEqual(report["domains"], {"b.example.org": 2})

    def test_pages_walk_the_same_bucket_even_when_a_page_contains_only_a_redacted_destination(self):
        hour = "2026-10-23T01:00:00Z"
        now = datetime(2026, 10, 23, 2, 5, tzinfo=timezone.utc)
        private_destination = "0123456789abcdef01234567.example.org"
        with History(self.db, self.log, "boot-1"):
            pass
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executemany("INSERT INTO blocks VALUES (?, ?, ?)", [
                (hour, private_destination, 1),
                (hour, "95.129.232.180", 3),
                (hour, "a.example.org", 2),
                (hour, "b.example.org", 1),
                (hour, "", 1),
                ("2026-10-23T00:00:00Z", "other.example.org", 1),
            ])

        first = ru_block_history.read_history_page(self.db, hour, limit=1, now=now)
        self.assertEqual(first["domains"], {})
        self.assertEqual(first["redacted"], 1)
        self.assertEqual(first["unidentified"], 1)
        self.assertTrue(first["next_cursor"])
        self.assertNotIn(private_destination, str(first))

        second = ru_block_history.read_history_page(self.db, hour, cursor=first["next_cursor"], limit=2, now=now)
        self.assertEqual(second["domains"], {"a.example.org": 2})
        self.assertEqual(second["ip_destinations"], {"95.129.232.180": 3})
        self.assertEqual(second["unidentified"], 0)
        repeated = ru_block_history.read_history_page(self.db, hour, cursor=first["next_cursor"], limit=2, now=now)
        self.assertEqual(repeated["domains"], second["domains"])
        third = ru_block_history.read_history_page(self.db, hour, cursor=second["next_cursor"], limit=1, now=now)
        self.assertEqual(third["domains"], {"b.example.org": 1})
        self.assertIsNone(third["next_cursor"])

    def test_page_rejects_open_out_of_range_or_invalid_bucket_and_bad_cursor(self):
        now = datetime(2026, 10, 23, 2, 5, tzinfo=timezone.utc)
        for hour in ("2026-10-15T01:00:00Z", "2026-10-23T02:00:00Z", "2026-10-23T1:00:00Z"):
            with self.subTest(hour=hour), self.assertRaises(ValueError):
                ru_block_history.read_history_page(self.db, hour, now=now)
        with self.assertRaises(ValueError):
            ru_block_history.read_history_page(self.db, "2026-10-23T01:00:00Z", limit=501, now=now)
        with self.assertRaises(ru_block_history.HistoryCursorError):
            ru_block_history.read_history_page(self.db, "2026-10-23T01:00:00Z", cursor="expired", now=now)

    def test_empty_and_missing_history_are_distinguished(self):
        now = datetime(2026, 10, 23, 2, 5, tzinfo=timezone.utc)
        hour = "2026-10-23T01:00:00Z"
        self.assertEqual(ru_block_history.read_history_page(self.db, hour, now=now)["state"], "waiting")
        with History(self.db, self.log, "boot-1"):
            pass
        empty = ru_block_history.read_history_page(self.db, hour, now=now)
        self.assertEqual(empty["state"], "available")
        self.assertEqual(empty["domains"], {})
        self.assertEqual(empty["ip_destinations"], {})
        self.assertIsNone(empty["next_cursor"])

    def test_pages_recover_names_beyond_the_legacy_top_limit(self):
        now = datetime(2026, 10, 23, 2, 5, tzinfo=timezone.utc)
        hour = "2026-10-23T01:00:00Z"
        expected = {f"host{i:04}.example.org": i + 1 for i in range(2103)}
        with History(self.db, self.log, "boot-1"):
            pass
        with closing(sqlite3.connect(self.db)) as db, db:
            db.executemany("INSERT INTO blocks VALUES (?, ?, ?)", (
                (hour, domain, hits) for domain, hits in expected.items()
            ))
        self.assertTrue(read_history(self.db)["truncated"])
        self.assertEqual(len(read_history(self.db)["domains"]), 2000)

        actual = {}
        page = ru_block_history.read_history_page(self.db, hour, now=now)
        while True:
            self.assertLessEqual(len(page["domains"]), ru_block_history.PAGE_LIMIT)
            self.assertTrue(actual.keys().isdisjoint(page["domains"]))
            actual.update(page["domains"])
            if not page["next_cursor"]:
                break
            page = ru_block_history.read_history_page(self.db, hour, cursor=page["next_cursor"], now=now)
        self.assertEqual(actual, expected)

    def test_full_database_preserves_existing_rows(self):
        self.log.write_bytes(row("a.example.org:443"))
        maximum = 16 * 1024
        with History(self.db, self.log, "boot-1", max_bytes=maximum) as store:
            store.collect()
            with self.log.open("ab") as output:
                output.write(b"".join(row(f"{i}.{'z'*60}.example.org:443") for i in range(500)))
            with self.assertRaises(sqlite3.OperationalError):
                store.collect()
        self.assertEqual(read_history(self.db)["domains"], {"a.example.org": 1})
        self.assertLessEqual(self.db.stat().st_size, maximum)

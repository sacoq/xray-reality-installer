from pathlib import Path
from tempfile import TemporaryDirectory
import sqlite3
import unittest

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

"""Persist hourly counts for one Xray ru-block access stream."""

from collections import Counter, OrderedDict
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import blake2s
from pathlib import Path
import ipaddress
import os
import re
import secrets
import sqlite3
from threading import Lock
from time import monotonic


BLOCK = b"panel-ru-destination-block"
ROUTE = re.compile(
    rb"\baccepted\s+(?:(?:tcp|udp):)?(\S+)\s+\[[^\]]*?(?:->|>>)\s*"
    + BLOCK + rb"\]"
)
HOST = re.compile(rb"(?=.{1,253}$)(?:[a-z0-9-]{1,63}\.)+[a-z][a-z0-9-]{1,62}")
MAX_BATCH = 4 * 1024 * 1024
MAX_DATABASE_BYTES = 64 * 1024 * 1024
ANCHOR_BYTES = 128
DATABASE = Path("/var/lib/xnpanel-ru-block-history/history.sqlite3")
BOOT_ID = Path("/proc/sys/kernel/random/boot_id")
PAGE_LIMIT = 500
PAGE_MAX_AGE_HOURS = 168
_HOUR_FORMAT = "%Y-%m-%dT%H:00:00Z"
_RESERVED_SUFFIXES = {"local", "test", "invalid", "localhost", "internal", "intranet", "lan", "home", "example"}
_OPAQUE_LABEL = re.compile(r"[a-f0-9]{24,}|[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}|[a-z0-9]{33,}", re.I)
_CURSOR_TTL = 15 * 60
_CURSOR_LIMIT = 256
_cursor_lock = Lock()
_page_cursors = OrderedDict()


class HistoryCursorError(ValueError):
    """This cursor cannot continue the requested bucket."""


def destination(line):
    if BLOCK not in line:
        return None
    matched = ROUTE.search(line)
    if not matched:
        return None
    host = matched[1].rsplit(b":", 1)[0].strip(b"[]").rstrip(b".").lower()
    try:
        stamp = datetime.strptime(line[:19].decode("ascii"), "%Y/%m/%d %H:%M:%S")
    except (UnicodeError, ValueError):
        return None
    address = host.decode("ascii", errors="ignore")
    if not HOST.fullmatch(host):
        try:
            parsed = ipaddress.ip_address(address)
            address = str(parsed) if parsed.is_global else ""
        except ValueError:
            address = ""
    return stamp.strftime("%Y-%m-%dT%H:00:00Z"), address


def anchor(stream, offset):
    start = max(offset - ANCHOR_BYTES, 0)
    stream.seek(start)
    return blake2s(stream.read(offset - start), digest_size=16).digest()


class History:
    def __init__(self, database, access_log, boot_id, max_bytes=MAX_DATABASE_BYTES):
        self.access_log = access_log
        self.boot_id = boot_id
        self.db = sqlite3.connect(database, timeout=5)
        self.db.execute("PRAGMA journal_mode=DELETE")
        self.db.execute("PRAGMA temp_store=MEMORY")
        page_size = self.db.execute("PRAGMA page_size").fetchone()[0]
        maximum = max_bytes // page_size
        actual = self.db.execute(f"PRAGMA max_page_count={maximum}").fetchone()[0]
        if actual > maximum:
            self.db.close()
            raise ValueError("The history database already exceeds its size limit")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS blocks (
                hour TEXT NOT NULL,
                domain TEXT NOT NULL,
                hits INTEGER NOT NULL,
                PRIMARY KEY (hour, domain)
            ) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS cursor (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                boot_id TEXT NOT NULL,
                device INTEGER NOT NULL,
                inode INTEGER NOT NULL,
                offset INTEGER NOT NULL,
                anchor BLOB NOT NULL,
                resets INTEGER NOT NULL
            );
        """)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.db.close()

    def collect(self):
        try:
            stream = self.access_log.open("rb")
        except FileNotFoundError:
            return 0
        with stream, self.db:
            self.db.execute("BEGIN IMMEDIATE")
            previous = self.db.execute(
                "SELECT boot_id, device, inode, offset, anchor, resets FROM cursor WHERE id=1"
            ).fetchone()
            stat = os.fstat(stream.fileno())
            signature = (self.boot_id, stat.st_dev, stat.st_ino)
            offset, resets = 0, previous[5] if previous else 0
            if previous:
                old = previous[3]
                if signature == previous[:3] and stat.st_size >= old and anchor(stream, old) == previous[4]:
                    offset = old
                else:
                    resets += 1
            if previous and resets == previous[5] and stat.st_size == offset:
                return 0
            stream.seek(offset)
            data = stream.read(min(MAX_BATCH, stat.st_size - offset))
            complete = data.rfind(b"\n") + 1
            if not complete:
                return 0
            next_offset = offset + complete
            # The agent can truncate or refill the same inode while it is being read.
            head = b""
            if complete < ANCHOR_BYTES and offset:
                head_start = max(0, next_offset - ANCHOR_BYTES)
                stream.seek(head_start)
                head = stream.read(offset - head_start)
            last = head + data[max(0, complete - ANCHOR_BYTES):complete]
            next_anchor = anchor(stream, next_offset)
            if next_anchor != blake2s(last, digest_size=16).digest():
                return 0
            counts = Counter(parsed for line in data[:complete].splitlines() if (parsed := destination(line)))
            self.db.executemany(
                "INSERT INTO blocks VALUES (?, ?, ?) ON CONFLICT(hour, domain) "
                "DO UPDATE SET hits=hits+excluded.hits",
                ((hour, domain, hits) for (hour, domain), hits in counts.items()),
            )
            self.db.execute(
                "INSERT OR REPLACE INTO cursor VALUES (1, ?, ?, ?, ?, ?, ?)",
                (*signature, next_offset, next_anchor, resets),
            )
            return complete


def read_history(database, since="", limit=2000):
    if not database.is_file():
        return {"state": "waiting", "domains": {}, "ip_destinations": {}, "total_hits": 0}
    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("PRAGMA temp_store=MEMORY")
        db.execute("BEGIN")
        rows = db.execute(
            "SELECT domain, SUM(hits) FROM blocks WHERE hour >= ? AND domain <> '' "
            "GROUP BY domain ORDER BY SUM(hits) DESC, domain LIMIT ?", (since, limit + 1),
        ).fetchall()
        first, last, total, unknown = db.execute(
            "SELECT MIN(hour), MAX(hour), COALESCE(SUM(hits),0), "
            "COALESCE(SUM(CASE WHEN domain='' THEN hits ELSE 0 END),0) "
            "FROM blocks WHERE hour >= ?", (since,),
        ).fetchone()
        state = db.execute("SELECT resets FROM cursor WHERE id=1").fetchone()
    domains, addresses = {}, {}
    for name, hits in rows[:limit]:
        target = domains if HOST.fullmatch(name.encode("ascii", errors="ignore")) else addresses
        target[name] = hits
    return {
        "state": "available",
        "first_utc_hour": first,
        "last_utc_hour": last,
        "total_hits": total,
        "unidentified": unknown,
        "source_resets": state[0] if state else 0,
        "truncated": len(rows) > limit,
        "domains": domains,
        "ip_destinations": addresses,
    }


def _cursor_position(cursor, hour):
    if cursor is None:
        return ""
    with _cursor_lock:
        previous = _page_cursors.get(cursor)
        if previous is not None:
            expires, saved_hour, position = previous
            if expires <= monotonic():
                del _page_cursors[cursor]
            elif saved_hour == hour:
                return position
    raise HistoryCursorError("The history cursor expired or belongs to another hour")


def _next_cursor(hour, position):
    cursor = secrets.token_urlsafe(24)
    # Keep the real sort key on the agent, including when that key was redacted.
    with _cursor_lock:
        _page_cursors[cursor] = (monotonic() + _CURSOR_TTL, hour, position)
        if len(_page_cursors) > _CURSOR_LIMIT:
            _page_cursors.popitem(last=False)
    return cursor


def read_history_page(database, hour, *, cursor=None, limit=PAGE_LIMIT, now=None):
    """Return a bounded page of destination counts for one closed UTC hour."""
    parsed = datetime.strptime(hour, _HOUR_FORMAT).replace(tzinfo=timezone.utc)
    current = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
    if parsed.strftime(_HOUR_FORMAT) != hour or not current - timedelta(hours=PAGE_MAX_AGE_HOURS) <= parsed < current:
        raise ValueError("Use a closed UTC hour in the last 168 hours")
    if not 1 <= limit <= PAGE_LIMIT:
        raise ValueError("History page size is out of range")
    position = _cursor_position(cursor, hour)
    report = {
        "state": "waiting", "utc_hour": hour, "next_cursor": None,
        "domains": {}, "ip_destinations": {}, "unidentified": 0, "redacted": 0,
    }
    if not database.is_file():
        return report

    with closing(sqlite3.connect(database.resolve().as_uri() + "?mode=ro", uri=True, timeout=5)) as db:
        db.execute("BEGIN")
        rows = db.execute(
            "SELECT domain, hits FROM blocks "
            "WHERE hour = ? AND domain > ? ORDER BY domain LIMIT ?",
            (hour, position, limit + 1),
        ).fetchall()
        if cursor is None:
            unknown = db.execute("SELECT hits FROM blocks WHERE hour = ? AND domain = ''", (hour,)).fetchone()
            report["unidentified"] = unknown[0] if unknown else 0

    report["state"] = "available"
    for name, hits in rows[:limit]:
        if name.isascii() and HOST.fullmatch(name.encode("ascii")):
            labels = name.lower().split(".")
            if labels[-1] not in _RESERVED_SUFFIXES and not any(_OPAQUE_LABEL.fullmatch(label) for label in labels):
                report["domains"][name] = hits
                continue
        else:
            try:
                address = ipaddress.ip_address(name)
            except ValueError:
                pass
            else:
                if address.is_global:
                    report["ip_destinations"][str(address)] = hits
                    continue
        report["redacted"] += hits
    if len(rows) > limit:
        report["next_cursor"] = _next_cursor(hour, rows[limit - 1][0])
    return report

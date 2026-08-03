"""In-memory VPN session evidence for conservative anti-sharing detection.

No browsing history is persisted.  The node agent consumes Xray's access
stream from tmpfs and Hysteria's loopback HTTP-auth events, keeps only a short
rolling window in RAM, and exposes aggregated source-network evidence to the
authenticated panel.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import threading
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable, Optional


IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_EMAIL_RE = re.compile(r"\bemail:\s*([^\s]+)", re.IGNORECASE)
_SOURCE_RE = re.compile(
    r"(?:\bfrom\s+)?(\[[0-9a-fA-F:]+\]|(?:\d{1,3}\.){3}\d{1,3}):\d+"
    r"\s+accepted\s+",
    re.IGNORECASE,
)
_DEST_RE = re.compile(
    r"\baccepted\s+(?:tcp|udp):([^\s]+)", re.IGNORECASE
)

# Connectivity/captive-portal probes are explicitly ignored.  They are
# generated in the background by operating systems and VPN clients and are
# not evidence that a human is using a copied key.
_PROBE_HOSTS = {
    "captive.apple.com",
    "clients3.google.com",
    "clients4.google.com",
    "connectivitycheck.android.com",
    "connectivitycheck.gstatic.com",
    "cp.cloudflare.com",
    "detectportal.firefox.com",
    "internet.yandex.ru",
    "msftconnecttest.com",
    "www.gstatic.com",
    "www.msftconnecttest.com",
    "www.msftncsi.com",
    "yandex.ru",
}


def _parse_address(value: Any) -> Optional[IPAddress]:
    raw = str(value or "").strip()
    if not raw:
        return None
    candidate = raw
    if raw.startswith("[") and "]" in raw:
        candidate = raw[1 : raw.index("]")]
    elif raw.count(":") == 1 and "." in raw:
        host, maybe_port = raw.rsplit(":", 1)
        if maybe_port.isdigit():
            candidate = host
    else:
        try:
            return ipaddress.ip_address(raw)
        except ValueError:
            # Unbracketed IPv6 may include a final port in Hysteria's addr.
            host, separator, port = raw.rpartition(":")
            if separator and port.isdigit():
                candidate = host
    try:
        return ipaddress.ip_address(candidate)
    except ValueError:
        return None


def canonical_public_ip(value: Any) -> Optional[str]:
    address = _parse_address(value)
    if address is None or not address.is_global:
        return None
    return address.compressed


def _destination_host(value: str) -> str:
    raw = str(value or "").strip().lower().rstrip(".")
    if raw.startswith("[") and "]" in raw:
        return raw[1 : raw.index("]")]
    if raw.count(":") == 1:
        host, port = raw.rsplit(":", 1)
        if port.isdigit():
            raw = host
    return raw.rstrip(".")


def is_probe_destination(value: str) -> bool:
    host = _destination_host(value)
    return host in _PROBE_HOSTS or any(
        host.endswith("." + suffix) for suffix in _PROBE_HOSTS
    )


def parse_xray_access_line(line: str) -> Optional[dict[str, str]]:
    """Parse one Xray access line into email/source/destination.

    Xray versions differ slightly (some prefix the peer with ``from``), so
    the parser deliberately anchors on the stable ``accepted`` and ``email:``
    fields instead of a complete timestamp format.
    """
    email_match = _EMAIL_RE.search(str(line or ""))
    source_match = _SOURCE_RE.search(str(line or ""))
    if not email_match or not source_match:
        return None
    source = canonical_public_ip(source_match.group(1))
    if not source:
        return None
    destination_match = _DEST_RE.search(str(line or ""))
    destination = destination_match.group(1) if destination_match else ""
    return {
        "identity": email_match.group(1).strip().lower(),
        "source_ip": source,
        "destination": destination,
    }


def same_network_point(left: str, right: str) -> bool:
    """Return the customer's requested source-IP de-duplication relation.

    IPv4 addresses are considered the same point when at least two octets in
    the same positions match.  For IPv6 the stable ISP prefix is used (/48),
    since individual privacy addresses routinely rotate their lower bits.
    """
    a = ipaddress.ip_address(left)
    b = ipaddress.ip_address(right)
    if a.version != b.version:
        return False
    if isinstance(a, ipaddress.IPv4Address):
        return sum(x == y for x, y in zip(a.packed, b.packed)) >= 2
    return a in ipaddress.ip_network(f"{b}/48", strict=False)


def group_network_points(addresses: Iterable[str]) -> list[list[str]]:
    """Group addresses using the transitive closure of ``same_network_point``."""
    values = sorted({str(ipaddress.ip_address(value)) for value in addresses})
    parent = list(range(len(values)))

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        a, b = find(left), find(right)
        if a != b:
            parent[max(a, b)] = min(a, b)

    for left in range(len(values)):
        for right in range(left + 1, len(values)):
            if same_network_point(values[left], values[right]):
                union(left, right)
    grouped: dict[int, list[str]] = defaultdict(list)
    for index, value in enumerate(values):
        grouped[find(index)].append(value)
    return sorted((sorted(group) for group in grouped.values()), key=lambda row: row[0])


@dataclass(frozen=True)
class SessionEvent:
    timestamp: float
    source_ip: str
    protocol: str
    destination: str = ""


class SessionTracker:
    """Bounded, thread-safe RAM store of recent per-identity observations."""

    def __init__(self, *, retention_seconds: int = 7200, per_identity_limit: int = 4096):
        self.retention_seconds = max(300, int(retention_seconds))
        self.per_identity_limit = max(64, int(per_identity_limit))
        self._events: dict[str, deque[SessionEvent]] = {}
        self._lock = threading.RLock()
        self._ignored_probe_events = 0

    def record(
        self,
        *,
        identity: str,
        source_ip: str,
        protocol: str,
        destination: str = "",
        timestamp: Optional[float] = None,
    ) -> bool:
        user = str(identity or "").strip().lower()
        address = canonical_public_ip(source_ip)
        if not user or not address:
            return False
        if destination and is_probe_destination(destination):
            with self._lock:
                self._ignored_probe_events += 1
            return False
        now = float(timestamp if timestamp is not None else time.time())
        event = SessionEvent(
            timestamp=now,
            source_ip=address,
            protocol=str(protocol or "unknown")[:32],
            destination=_destination_host(destination)[:255],
        )
        with self._lock:
            bucket = self._events.setdefault(user, deque())
            bucket.append(event)
            while len(bucket) > self.per_identity_limit:
                bucket.popleft()
            self._prune_locked(now)
        return True

    def _prune_locked(self, now: float) -> None:
        cutoff = now - self.retention_seconds
        for identity in list(self._events):
            bucket = self._events[identity]
            while bucket and bucket[0].timestamp < cutoff:
                bucket.popleft()
            if not bucket:
                self._events.pop(identity, None)

    def snapshot(
        self,
        *,
        window_seconds: int = 900,
        min_events: int = 1,
        now: Optional[float] = None,
    ) -> dict[str, Any]:
        current = float(now if now is not None else time.time())
        window = max(60, min(self.retention_seconds, int(window_seconds)))
        minimum = max(1, min(100, int(min_events)))
        cutoff = current - window
        with self._lock:
            self._prune_locked(current)
            copied = {
                identity: [event for event in bucket if event.timestamp >= cutoff]
                for identity, bucket in self._events.items()
            }
            ignored = self._ignored_probe_events

        clients: list[dict[str, Any]] = []
        for identity, events in sorted(copied.items()):
            if not events:
                continue
            by_ip: dict[str, list[SessionEvent]] = defaultdict(list)
            for event in events:
                by_ip[event.source_ip].append(event)
            qualified_ips = sorted(
                ip for ip, rows in by_ip.items() if len(rows) >= minimum
            )
            if not qualified_ips:
                continue
            points = []
            for members in group_network_points(qualified_ips):
                member_events = [event for ip in members for event in by_ip[ip]]
                digest = hashlib.sha256("\n".join(members).encode("ascii")).hexdigest()[:16]
                points.append(
                    {
                        "point_id": f"net-{digest}",
                        "source_ips": members,
                        "event_count": len(member_events),
                        "first_seen_at": min(event.timestamp for event in member_events),
                        "last_seen_at": max(event.timestamp for event in member_events),
                        "protocols": sorted({event.protocol for event in member_events}),
                    }
                )
            clients.append(
                {
                    "identity": identity,
                    "point_count": len(points),
                    "raw_ip_count": len(qualified_ips),
                    "event_count": sum(len(rows) for rows in by_ip.values()),
                    "points": points,
                    "protocols": sorted({event.protocol for event in events}),
                    "first_seen_at": min(event.timestamp for event in events),
                    "last_seen_at": max(event.timestamp for event in events),
                }
            )
        return {
            "generated_at": current,
            "window_seconds": window,
            "min_events": minimum,
            "ignored_probe_events": ignored,
            "clients": clients,
        }


__all__ = [
    "SessionTracker",
    "canonical_public_ip",
    "group_network_points",
    "is_probe_destination",
    "parse_xray_access_line",
    "same_network_point",
]

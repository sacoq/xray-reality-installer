"""Auto-balance tier helpers + global settings.

The panel exposes two auto-balance "tiers" on every server:

  * ``primary``   — the preferred tier. Foreign exit nodes go here.
  * ``fallback``  — the backup tier. Whitelist-front (RU front)
                    nodes go here so users automatically switch to
                    them when the foreign IPs are unreachable
                    (whitelist mode active in the user's region).

The subscription renderer (sing-box / Clash) builds a hierarchical
``urltest`` group:

::

    Auto (urltest, ``probe_interval_seconds``)
      ├─ ⚡ Primary  (urltest of pool_tier='primary' servers)
      └─ 🛡 Fallback (urltest of pool_tier='fallback' servers)

Sing-box natively probes every member at the configured interval and
selects the lowest-latency outbound. When the primary tier goes dark
for a user, the top-level urltest auto-switches to the fallback tier;
the next probe cycle (default 30s) switches back as soon as primary
recovers. No panel-side daemon, no agent changes — this is all the
client doing client-side health checks.

The legacy ``in_pool`` boolean is kept as the "primary tier" indicator
so existing balancer / pool code paths (``pool_upstreams`` etc.) keep
working unchanged.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

from .models import Server, Setting


# Tier values stored in ``Server.pool_tier`` / ``EnrollmentToken.pool_tier``.
TIER_PRIMARY = "primary"
TIER_FALLBACK = "fallback"
TIER_NONE = ""

VALID_TIERS = frozenset({TIER_NONE, TIER_PRIMARY, TIER_FALLBACK})


# Subscription label prefixes — chosen so plain-vless clients (v2rayN /
# Streisand / generic) still see grouping. ``⚡`` matches the existing
# pool prefix; ``🛡`` is the fallback marker (visible shield = the
# "shield" of bypass nodes that takes over when foreign nodes get
# blocked).
PRIMARY_PREFIX = "⚡ "
FALLBACK_PREFIX = "🛡 "


# Setting keys (panel-wide, stored in the ``settings`` table).
SETTING_PROBE_URL = "auto_balance.probe_url"
SETTING_PROBE_INTERVAL = "auto_balance.probe_interval_seconds"
SETTING_TOLERANCE_MS = "auto_balance.tolerance_ms"


# Defaults. Probe URL matches what sing-box/Clash docs recommend
# (Google's HTTP/204 endpoint, low-latency, available worldwide).
DEFAULT_PROBE_URL = "https://www.gstatic.com/generate_204"
# 30 seconds is the user-requested cadence: short enough that recovery
# from a transient whitelist toggle takes <1 minute, long enough that
# probe traffic doesn't dominate the connection on slow mobile links.
DEFAULT_PROBE_INTERVAL_SECONDS = 30
# Hysteresis — the currently-selected outbound is preferred unless
# another is at least this many ms faster. Stops the urltest from
# flapping between two near-identical primaries every 30s.
DEFAULT_TOLERANCE_MS = 50


# Bounds enforced on user input so we never push a config that
# sing-box rejects. 5s is the minimum sing-box accepts in practice;
# 600s caps the worst-case recovery time.
MIN_PROBE_INTERVAL_SECONDS = 5
MAX_PROBE_INTERVAL_SECONDS = 600
MIN_TOLERANCE_MS = 0
MAX_TOLERANCE_MS = 5000


def normalise_tier(value: Optional[str]) -> str:
    """Coerce arbitrary input to a valid tier value.

    Accepts ``None``, empty string, or any of the known tier names
    (case-insensitive, whitespace-trimmed). Anything else raises
    ``ValueError``.
    """
    if value is None:
        return TIER_NONE
    v = str(value).strip().lower()
    if v in VALID_TIERS:
        return v
    raise ValueError(
        f"unknown pool_tier: {value!r} "
        f"(expected '', 'primary' or 'fallback')"
    )


def server_pool_tier(server: Server) -> str:
    """Return the effective tier for ``server``.

    Falls back to ``primary`` when the row has the legacy
    ``in_pool=True`` flag but no explicit ``pool_tier`` (older code
    paths that haven't been migrated yet). Older balancer / pool
    queries use ``in_pool`` directly so this only matters for the
    subscription renderer.
    """
    tier = (getattr(server, "pool_tier", "") or "").strip().lower()
    if tier in VALID_TIERS and tier != TIER_NONE:
        return tier
    if bool(getattr(server, "in_pool", False)):
        return TIER_PRIMARY
    return TIER_NONE


def is_in_auto_balance(server: Server) -> bool:
    """Whether ``server`` participates in any auto-balance tier."""
    return server_pool_tier(server) in (TIER_PRIMARY, TIER_FALLBACK)


def label_prefix_for(server: Server) -> str:
    """Subscription-label prefix for ``server`` based on its tier.

    Empty string when the server isn't in any tier.
    """
    tier = server_pool_tier(server)
    if tier == TIER_PRIMARY:
        return PRIMARY_PREFIX
    if tier == TIER_FALLBACK:
        return FALLBACK_PREFIX
    return ""


def _setting(db: Session, key: str) -> Optional[str]:
    row = db.get(Setting, key)
    return row.value if row is not None else None


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=value)
        db.add(row)
    else:
        row.value = value


def get_settings(db: Session) -> dict:
    """Read panel-wide auto-balance settings, applying defaults.

    Returns ``{probe_url, probe_interval_seconds, tolerance_ms}``.
    """
    raw_url = _setting(db, SETTING_PROBE_URL)
    raw_interval = _setting(db, SETTING_PROBE_INTERVAL)
    raw_tolerance = _setting(db, SETTING_TOLERANCE_MS)

    url = (raw_url or "").strip() or DEFAULT_PROBE_URL

    try:
        interval = int(raw_interval) if raw_interval else DEFAULT_PROBE_INTERVAL_SECONDS
    except (TypeError, ValueError):
        interval = DEFAULT_PROBE_INTERVAL_SECONDS
    interval = max(MIN_PROBE_INTERVAL_SECONDS, min(MAX_PROBE_INTERVAL_SECONDS, interval))

    try:
        tolerance = int(raw_tolerance) if raw_tolerance else DEFAULT_TOLERANCE_MS
    except (TypeError, ValueError):
        tolerance = DEFAULT_TOLERANCE_MS
    tolerance = max(MIN_TOLERANCE_MS, min(MAX_TOLERANCE_MS, tolerance))

    return {
        "probe_url": url,
        "probe_interval_seconds": interval,
        "tolerance_ms": tolerance,
    }


def update_settings(
    db: Session,
    *,
    probe_url: Optional[str] = None,
    probe_interval_seconds: Optional[int] = None,
    tolerance_ms: Optional[int] = None,
) -> dict:
    """Persist any provided fields, then return the effective settings.

    Caller is expected to commit the session.
    """
    if probe_url is not None:
        url = probe_url.strip()
        if not url:
            raise ValueError("probe_url cannot be empty")
        if not (url.startswith("http://") or url.startswith("https://")):
            raise ValueError("probe_url must be an http:// or https:// URL")
        _set_setting(db, SETTING_PROBE_URL, url)
    if probe_interval_seconds is not None:
        iv = int(probe_interval_seconds)
        if iv < MIN_PROBE_INTERVAL_SECONDS or iv > MAX_PROBE_INTERVAL_SECONDS:
            raise ValueError(
                "probe_interval_seconds must be between "
                f"{MIN_PROBE_INTERVAL_SECONDS} and {MAX_PROBE_INTERVAL_SECONDS}"
            )
        _set_setting(db, SETTING_PROBE_INTERVAL, str(iv))
    if tolerance_ms is not None:
        tol = int(tolerance_ms)
        if tol < MIN_TOLERANCE_MS or tol > MAX_TOLERANCE_MS:
            raise ValueError(
                "tolerance_ms must be between "
                f"{MIN_TOLERANCE_MS} and {MAX_TOLERANCE_MS}"
            )
        _set_setting(db, SETTING_TOLERANCE_MS, str(tol))
    return get_settings(db)


def interval_string(seconds: int) -> str:
    """Format an interval in seconds as a sing-box duration string."""
    seconds = max(1, int(seconds))
    return f"{seconds}s"


__all__ = [
    "DEFAULT_PROBE_INTERVAL_SECONDS",
    "DEFAULT_PROBE_URL",
    "DEFAULT_TOLERANCE_MS",
    "FALLBACK_PREFIX",
    "MAX_PROBE_INTERVAL_SECONDS",
    "MAX_TOLERANCE_MS",
    "MIN_PROBE_INTERVAL_SECONDS",
    "MIN_TOLERANCE_MS",
    "PRIMARY_PREFIX",
    "SETTING_PROBE_INTERVAL",
    "SETTING_PROBE_URL",
    "SETTING_TOLERANCE_MS",
    "TIER_FALLBACK",
    "TIER_NONE",
    "TIER_PRIMARY",
    "VALID_TIERS",
    "get_settings",
    "interval_string",
    "is_in_auto_balance",
    "label_prefix_for",
    "normalise_tier",
    "server_pool_tier",
    "update_settings",
]

"""xray-panel node agent.

Runs on each xray server. Exposes an HTTP API the central panel talks to:

* ``GET  /health``                   — liveness / xray version
* ``GET  /stats``                    — traffic counters from xray's StatsService
* ``GET  /sysinfo``                  — host metrics: cpu, memory, disk, load, uptime, net
* ``GET  /live``                     — live snapshot: online client count (clients
                                       whose traffic moved within ``online_window``),
                                       per-client up/down rate (B/s) and host NIC
                                       up/down rate (B/s).
* ``GET  /xray/inbounds``            — safe metadata for existing VLESS inbounds
* ``POST /speedtest``                — bounded Cloudflare edge speed test
* ``GET  /warp/status``              — native WARP interface + egress status
* ``POST /warp/install``             — install/activate distillium warp-native
* ``GET  /config``                   — current config.json
* ``POST /config``                   — accept a new config.json. If the only
                                       difference vs. the current on-disk
                                       config is the user set on one or more
                                       VLESS inbounds, the diff is applied via
                                       xray's runtime ``adu`` / ``rmu`` API
                                       (no xray restart). Structural changes
                                       (port / sni / key / inbound shape) still
                                       trigger ``systemctl restart xray``.
* ``POST /xray/inbound/users/add``   — explicit ``xray api adu`` (runtime add).
* ``POST /xray/inbound/users/remove``— explicit ``xray api rmu`` (runtime remove).
* ``POST /keys``                     — generate a fresh x25519 keypair (convenience)
* ``POST /xray/restart``             — systemctl restart xray
* ``POST /xray/start``               — systemctl start xray
* ``POST /xray/stop``                — systemctl stop xray
* ``GET  /xray/logs``                — last N lines from the xray journal
* ``GET  /system/version``           — installed/latest xnpanel SHA snapshot
* ``POST /system/upgrade``           — detached `xnpanel update --force`
* ``POST /system/reboot``            — schedule a host reboot (shutdown -r +1)

All endpoints (except ``/health``) require ``Authorization: Bearer <token>``.
The token is provisioned by the installer and stored in ``/etc/xray-agent/agent.env``.
"""
from __future__ import annotations

import copy
import ipaddress
import json
import logging
import os
import re
import secrets as _secrets
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel

log = logging.getLogger("xray-agent")


# ---------- config ----------
XRAY_BIN = os.environ.get("XRAY_BIN", "/usr/local/bin/xray")
XRAY_CONFIG = Path(os.environ.get("XRAY_CONFIG", "/usr/local/etc/xray/config.json"))
XRAY_SERVICE = os.environ.get("XRAY_SERVICE", "xray")
AGENT_TOKEN = os.environ.get("AGENT_TOKEN", "").strip()
XRAY_API_ADDR = os.environ.get("XRAY_API_ADDR", "127.0.0.1:10085")
LIVE_SAMPLE_INTERVAL_S = max(
    2.0, min(30.0, float(os.environ.get("LIVE_SAMPLE_INTERVAL_S", "5") or 5))
)
SPEEDTEST_DOWNLOAD_URL = os.environ.get(
    "SPEEDTEST_DOWNLOAD_URL", "https://speed.cloudflare.com/__down"
).strip()
SPEEDTEST_UPLOAD_URL = os.environ.get(
    "SPEEDTEST_UPLOAD_URL", "https://speed.cloudflare.com/__up"
).strip()
SPEEDTEST_DOWNLOAD_BYTES = max(
    1_000_000,
    min(100_000_000, int(os.environ.get("SPEEDTEST_DOWNLOAD_BYTES", "10000000") or 10_000_000)),
)
SPEEDTEST_UPLOAD_BYTES = max(
    500_000,
    min(50_000_000, int(os.environ.get("SPEEDTEST_UPLOAD_BYTES", "5000000") or 5_000_000)),
)
WARP_INSTALL_URL = os.environ.get(
    "WARP_INSTALL_URL",
    "https://raw.githubusercontent.com/distillium/warp-native/main/install.sh",
).strip()
WARP_CONFIG = Path(os.environ.get("WARP_CONFIG", "/etc/wireguard/warp.conf"))
WARP_SERVICE = os.environ.get("WARP_SERVICE", "wg-quick@warp")


app = FastAPI(title="xray-panel-agent", version="1.0")


# ---------- auth ----------
def require_token(request: Request) -> None:
    if not AGENT_TOKEN:
        # Fail closed — refuse to run auth'd endpoints without a configured token.
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="agent has no AGENT_TOKEN configured",
        )
    header = request.headers.get("authorization", "")
    prefix = "Bearer "
    if not header.startswith(prefix):
        raise HTTPException(status_code=401, detail="missing bearer token")
    supplied = header[len(prefix):].strip()
    if not _secrets.compare_digest(supplied, AGENT_TOKEN):
        raise HTTPException(status_code=401, detail="invalid token")


# ---------- helpers ----------
def _run(cmd: list[str], *, check: bool = True, timeout: int = 15) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        check=check,
        timeout=timeout,
    )


def _xray_version() -> str:
    if not shutil.which(XRAY_BIN) and not Path(XRAY_BIN).exists():
        return ""
    try:
        r = _run([XRAY_BIN, "version"], check=False)
        return (r.stdout or "").strip().splitlines()[0] if r.stdout else ""
    except Exception:
        return ""


def _systemctl_active(name: str) -> bool:
    r = _run(["systemctl", "is-active", name], check=False)
    return (r.stdout or "").strip() == "active"


def _atomic_write(path: Path, data: str, *, mode: int = 0o644) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(data)
    os.chmod(tmp, mode)
    tmp.replace(path)


# ---------- xray runtime user API ----------
# These helpers shell out to ``xray api adu`` / ``xray api rmu`` against the
# local xray's gRPC HandlerService. They let the agent apply user-set deltas
# *without* restarting xray-core: ``systemctl restart xray`` drops every
# active TCP/UDP session for ~10 s (Brawl Stars / VC clients reconnect with
# "connection interrupted"), which is unacceptable for a CRUD operation that
# only adds or removes one user.
#
# The CLI surface (xray-core ``main/commands/all/api/inbound_user_add.go``):
#
#     xray api adu --server=127.0.0.1:10085 c1.json [c2.json ...]
#     xray api rmu --server=127.0.0.1:10085 -tag=<tag> <email1> [email2 ...]
#
# ``adu`` takes config files: each must be a parseable Xray config.json with
# ``inbounds[]`` whose ``tag`` matches a *live* inbound on the running xray.
# Each user inside ``settings.clients`` must have ``email`` (xray-core
# requires it for adu — ``xray run`` does not, but adu does, see
# XTLS/Xray-core#5718).
#
# ``rmu`` takes ``-tag=`` plus N email positional args. We don't need a JSON
# file for removals — only emails are needed to identify which users to drop.
USER_OP_TIMEOUT = 15


def _xray_api_args() -> list[str]:
    return [f"--server={XRAY_API_ADDR}"]


def _parse_count(text: str, verb: str) -> int:
    """Parse ``Added N user(s) in total.`` / ``Removed N user(s) ...`` from
    xray's stdout. Returns -1 if the line is missing (we treat that as an
    "unknown" outcome and fall back to restart).
    """
    pat = re.compile(rf"{verb}\s+(\d+)\s+user", re.IGNORECASE)
    for line in (text or "").splitlines():
        m = pat.search(line)
        if m:
            return int(m.group(1))
    return -1


def _make_adu_payload(
    *, tag: str, protocol: str, port: int, users: list[dict[str, Any]]
) -> dict[str, Any]:
    """Build a minimal config.json that ``xray api adu`` can parse.

    xray-core's ``InboundDetourConfig.Build()`` runs on every inbound in the
    file, even though the API only matches by tag. ``Build()`` requires a
    valid port and protocol settings, so we hand it both — the values
    don't actually take effect on the running xray (the live inbound at
    that tag keeps its real port/streamSettings), they just need to parse.
    """
    inbound: dict[str, Any] = {
        "tag": tag,
        "port": int(port) if port else 1,
        "protocol": protocol,
        "settings": {"clients": users, "decryption": "none"},
    }
    return {"inbounds": [inbound]}


def _xray_api_add_users(
    *, tag: str, protocol: str, port: int, users: list[dict[str, Any]]
) -> tuple[bool, int, str]:
    """Run ``xray api adu`` for one inbound. Returns ``(ok, added_count, msg)``.

    ``ok`` is True iff the CLI exited 0 *and* added every requested user
    (xray's adu silently skips users without an ``email`` field, so a
    partial success would leave us in a known-inconsistent state —
    safer to fall back to a restart in that case).
    """
    if not users:
        return True, 0, "no users to add"
    payload = _make_adu_payload(tag=tag, protocol=protocol, port=port, users=users)
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", prefix="xray-adu-", delete=False
    ) as fp:
        json.dump(payload, fp)
        path = fp.name
    try:
        r = _run(
            [XRAY_BIN, "api", "adu", *_xray_api_args(), path],
            check=False, timeout=USER_OP_TIMEOUT,
        )
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
    added = _parse_count(r.stdout, "Added")
    msg = ((r.stderr or "") + (r.stdout or "")).strip()
    if r.returncode != 0:
        return False, max(added, 0), msg
    if added < len(users):
        return False, max(added, 0), msg
    return True, added, msg


def _xray_api_remove_users(*, tag: str, emails: list[str]) -> tuple[bool, int, str]:
    """Run ``xray api rmu -tag=<tag> <email>...``. Returns ``(ok, removed, msg)``.

    ``ok`` requires CLI rc==0 and ``Removed N`` matching ``len(emails)``.
    A live xray that doesn't know the email returns an error, which would
    drop the count below ``len(emails)`` — we then fall back to a
    full-restart push so the on-disk config and the live xray converge.
    """
    if not emails:
        return True, 0, "no users to remove"
    r = _run(
        [XRAY_BIN, "api", "rmu", *_xray_api_args(), f"-tag={tag}", *emails],
        check=False, timeout=USER_OP_TIMEOUT,
    )
    removed = _parse_count(r.stdout, "Removed")
    msg = ((r.stderr or "") + (r.stdout or "")).strip()
    if r.returncode != 0:
        return False, max(removed, 0), msg
    if removed < len(emails):
        return False, max(removed, 0), msg
    return True, removed, msg


# ---------- config diffing ----------
# Used by ``put_config`` to decide whether the new config can be applied via
# ``adu``/``rmu`` (cheap: no xray restart, active connections preserved) or
# requires a full ``systemctl restart xray`` (any structural change — port,
# sni, reality keys, outbounds, routing, observatory, balancer membership,
# etc.).
_INBOUND_CLIENT_PROTOCOLS = {"vless"}


def _client_email(c: dict[str, Any]) -> str:
    return str(c.get("email") or "")


def _inbound_without_clients(ib: dict[str, Any]) -> dict[str, Any]:
    """Deep-copy ``ib`` with ``settings.clients`` stripped, for structural
    equality testing.

    Anything else inside ``settings`` (decryption, fallbacks) is preserved
    — a change there is structural and must restart xray.
    """
    clone = copy.deepcopy(ib)
    settings = clone.get("settings")
    if isinstance(settings, dict):
        settings.pop("clients", None)
    return clone


def _normalize_clients(clients: list[dict[str, Any]] | None) -> dict[str, dict[str, Any]]:
    """Map ``email -> client dict`` ignoring entries without an email (xray's
    runtime API is keyed on email and skips email-less rows on adu).
    """
    out: dict[str, dict[str, Any]] = {}
    for c in clients or []:
        email = _client_email(c)
        if not email:
            continue
        out[email] = c
    return out


class UserDelta(BaseModel):
    """Per-inbound delta returned by ``_diff_user_delta``."""

    tag: str
    protocol: str
    port: int
    add_users: list[dict[str, Any]] = []
    remove_emails: list[str] = []

    def is_empty(self) -> bool:
        return not self.add_users and not self.remove_emails


def _diff_user_delta(
    old_config: dict[str, Any], new_config: dict[str, Any]
) -> list[UserDelta] | None:
    """Return per-inbound user deltas if ``old_config`` and ``new_config``
    differ ONLY in user lists of supported (VLESS) inbounds. Otherwise
    return ``None`` (=> structural change — caller must restart xray).

    ``None`` is returned for any of:
      * top-level key set or values (``log``, ``api``, ``stats``,
        ``policy``, ``outbounds``, ``routing``, ``observatory``, …)
        differ;
      * ``inbounds`` array length / order differs;
      * any single inbound differs in any field other than
        ``settings.clients`` (port, protocol, streamSettings, sniffing,
        listen, fallbacks, decryption, anything);
      * a non-VLESS inbound's client list differs (Trojan / Shadowsocks
        runtime API works the same way but the rest of this codebase
        only emits VLESS inbounds; treat anything else as structural to
        avoid silent drift);
      * any client lacks an ``email`` (xray's runtime adu requires it).
    """
    # 1. Top-level: every key except ``inbounds`` must be byte-identical.
    keys = set(old_config.keys()) | set(new_config.keys())
    for k in keys:
        if k == "inbounds":
            continue
        if old_config.get(k) != new_config.get(k):
            return None

    old_inbounds = old_config.get("inbounds") or []
    new_inbounds = new_config.get("inbounds") or []
    if len(old_inbounds) != len(new_inbounds):
        return None

    deltas: list[UserDelta] = []
    for old_ib, new_ib in zip(old_inbounds, new_inbounds):
        if _inbound_without_clients(old_ib) != _inbound_without_clients(new_ib):
            return None
        old_clients_raw = (old_ib.get("settings") or {}).get("clients") or []
        new_clients_raw = (new_ib.get("settings") or {}).get("clients") or []
        if old_clients_raw == new_clients_raw:
            continue
        protocol = str(new_ib.get("protocol") or "").lower()
        if protocol not in _INBOUND_CLIENT_PROTOCOLS:
            # Non-VLESS user-set change — we don't have a tested adu/rmu
            # path for it, fall back to restart rather than guess.
            return None
        # Ensure every client has an email — missing emails would make
        # the runtime API silently skip them (creating an inconsistent
        # state vs. the on-disk config).
        for c in old_clients_raw:
            if not _client_email(c):
                return None
        for c in new_clients_raw:
            if not _client_email(c):
                return None
        old_by_email = _normalize_clients(old_clients_raw)
        new_by_email = _normalize_clients(new_clients_raw)
        adds: list[dict[str, Any]] = []
        removes: list[str] = []
        for email, _ in old_by_email.items():
            if email not in new_by_email:
                removes.append(email)
        for email, c in new_by_email.items():
            if email not in old_by_email:
                adds.append(c)
            elif old_by_email[email] != c:
                # Mutation (uuid rotation, flow change) — remove then
                # add to force xray to pick up the new account.
                removes.append(email)
                adds.append(c)
        if not adds and not removes:
            continue
        tag = str(new_ib.get("tag") or old_ib.get("tag") or "")
        if not tag:
            # Untagged inbound — xray's API matches by tag, so no tag
            # means we can't address this inbound via adu/rmu at all.
            return None
        port = int(new_ib.get("port") or 0)
        deltas.append(
            UserDelta(
                tag=tag,
                protocol=protocol,
                port=port,
                add_users=adds,
                remove_emails=removes,
            )
        )
    return deltas


def _read_current_config() -> dict[str, Any] | None:
    """Return parsed ``XRAY_CONFIG`` or ``None`` if missing/unreadable/
    invalid. ``None`` forces ``put_config`` onto the restart path —
    we can't safely diff against a config we can't parse.
    """
    if not XRAY_CONFIG.exists():
        return None
    try:
        return json.loads(XRAY_CONFIG.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("current config %s is unreadable: %s", XRAY_CONFIG, exc)
        return None


def _apply_runtime_deltas(
    deltas: list[UserDelta],
) -> tuple[bool, int, int, str]:
    """Apply each ``UserDelta`` to the running xray via adu/rmu.

    Returns ``(ok, total_added, total_removed, msg)``. On the first failure
    we stop and return ``ok=False`` with whatever counts succeeded so the
    caller can fall back to a restart and converge state from the freshly
    written config.json.

    Order: removes first, then adds. This matters when an existing email
    is rotated to a new uuid (we emit ``[remove email, add email]`` for it
    in the diff) — xray rejects ``AddUser`` for an email that's already
    live, so removing the old account first is required.
    """
    total_added = 0
    total_removed = 0
    msgs: list[str] = []
    for d in deltas:
        if d.remove_emails:
            ok, n, msg = _xray_api_remove_users(tag=d.tag, emails=d.remove_emails)
            total_removed += n
            if msg:
                msgs.append(f"rmu {d.tag}: {msg}")
            if not ok:
                return False, total_added, total_removed, " | ".join(msgs)
    for d in deltas:
        if d.add_users:
            ok, n, msg = _xray_api_add_users(
                tag=d.tag, protocol=d.protocol, port=d.port, users=d.add_users
            )
            total_added += n
            if msg:
                msgs.append(f"adu {d.tag}: {msg}")
            if not ok:
                return False, total_added, total_removed, " | ".join(msgs)
    return True, total_added, total_removed, " | ".join(msgs)


# ---------- schemas ----------
class HealthOut(BaseModel):
    ok: bool
    xray_version: str
    xray_active: bool


class ConfigIn(BaseModel):
    config: dict[str, Any]


class ConfigOut(BaseModel):
    config: dict[str, Any]
    # ``method`` reports how the new config was applied:
    #   * ``"runtime_api"`` — only client lists changed; applied via
    #     ``xray api adu`` / ``xray api rmu`` on the running xray (no
    #     restart, active connections preserved).
    #   * ``"restart"`` — structural change (port / sni / keys / inbound
    #     shape / outbounds / routing) or runtime-API path unavailable;
    #     config.json was rewritten and ``systemctl restart xray`` ran.
    method: str = "restart"
    restarted: bool = True
    # Counters from runtime API (when ``method="runtime_api"``); 0
    # otherwise. Helpful for the panel to log "applied N adds, M removes
    # without restart".
    users_added: int = 0
    users_removed: int = 0


class StatItem(BaseModel):
    name: str
    value: int


class StatsOut(BaseModel):
    stats: list[StatItem]


class KeyPairOut(BaseModel):
    private_key: str
    public_key: str


class WarpInstallIn(BaseModel):
    license_key: str = ""


class WarpStatusOut(BaseModel):
    installed: bool
    service_active: bool
    interface_active: bool
    reachable: bool
    warp_ip: str = ""
    account: str = ""
    message: str = ""


class SysInfoOut(BaseModel):
    cpu_percent: float
    cpu_count: int
    load_1: float
    load_5: float
    load_15: float
    mem_total: int
    mem_used: int
    mem_available: int
    swap_total: int
    swap_used: int
    disk_total: int
    disk_used: int
    uptime_seconds: int
    net_rx_bytes: int
    net_tx_bytes: int
    kernel: str
    hostname: str


# ---------- routes ----------
@app.get("/health", response_model=HealthOut)
def health() -> HealthOut:
    return HealthOut(
        ok=True,
        xray_version=_xray_version(),
        xray_active=_systemctl_active(XRAY_SERVICE),
    )


@app.get("/config", response_model=ConfigOut, dependencies=[Depends(require_token)])
def get_config() -> ConfigOut:
    if not XRAY_CONFIG.exists():
        raise HTTPException(status_code=404, detail="xray config.json missing")
    try:
        return ConfigOut(config=json.loads(XRAY_CONFIG.read_text()))
    except json.JSONDecodeError as e:
        raise HTTPException(status_code=500, detail=f"config.json is not valid JSON: {e}")


@app.post("/config", response_model=ConfigOut, dependencies=[Depends(require_token)])
def put_config(body: ConfigIn) -> ConfigOut:
    """Apply a new xray config.json.

    Two paths:

    1. **Runtime (no restart):** if the only difference vs. the current
       on-disk config is the user list of one or more VLESS inbounds, the
       diff is pushed via ``xray api adu`` / ``xray api rmu`` against the
       live xray. ``config.json`` is then atomically replaced so the
       change survives the next restart, but xray itself keeps running
       with all active connections intact.
    2. **Restart:** any structural change (port, sni, reality keys,
       streamSettings, outbounds, routing, balancers, observatory, the
       inbound list itself — anything beyond ``settings.clients``)
       triggers the legacy ``write + systemctl restart xray`` path.
       Same fallback fires when the runtime path fails for any reason
       (xray inactive, gRPC unreachable, partial adu/rmu, missing/unreadable
       current config).
    """
    payload = json.dumps(body.config, indent=2, ensure_ascii=False)

    # Validate via `xray -test` before we touch anything (works whether
    # we end up on the runtime or restart path — a structurally invalid
    # config can't be applied either way).
    tmp = XRAY_CONFIG.with_suffix(".new.json")
    _atomic_write(tmp, payload, mode=0o644)
    r = _run([XRAY_BIN, "-test", "-config", str(tmp)], check=False, timeout=20)
    if r.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=f"xray -test rejected config: {r.stderr.strip() or r.stdout.strip()}",
        )

    # Decide: runtime API (no restart) vs. systemctl restart.
    current = _read_current_config()
    deltas: list[UserDelta] | None = None
    if current is not None and _systemctl_active(XRAY_SERVICE):
        deltas = _diff_user_delta(current, body.config)

    if deltas is not None:
        # Pure user-set change. Try the runtime path; commit the file
        # only after xray has accepted the deltas, so a failure mid-way
        # leaves the on-disk config = live xray (we then fall back to a
        # full restart from the new file).
        if not deltas:
            # New config is byte-equivalent to the live one apart from
            # whitespace / key ordering — still write the new file so
            # subsequent diffs work, but nothing to do otherwise.
            tmp.replace(XRAY_CONFIG)
            return ConfigOut(
                config=body.config,
                method="runtime_api",
                restarted=False,
                users_added=0,
                users_removed=0,
            )
        ok, added, removed, msg = _apply_runtime_deltas(deltas)
        if ok:
            tmp.replace(XRAY_CONFIG)
            log.info(
                "runtime adu/rmu ok: +%d -%d (%s)",
                added, removed, msg,
            )
            return ConfigOut(
                config=body.config,
                method="runtime_api",
                restarted=False,
                users_added=added,
                users_removed=removed,
            )
        log.warning(
            "runtime adu/rmu failed (+%d -%d): %s — falling back to restart",
            added, removed, msg,
        )

    # Restart path: structural change, runtime path unavailable, or
    # runtime path failed. Either way, the freshly written config.json
    # becomes authoritative on the next start.
    tmp.replace(XRAY_CONFIG)
    _run(["systemctl", "restart", XRAY_SERVICE], check=False, timeout=20)
    return ConfigOut(
        config=body.config,
        method="restart",
        restarted=True,
    )


# ---------- runtime user API (explicit endpoints) ----------
# These let the panel apply a single client mutation directly, without
# rebuilding/diffing the whole config.json. Useful for the hot path of
# subscription provisioning where 99% of mutations are "add one user" /
# "remove one user" — the panel can skip ``put_config`` entirely.
#
# The agent also keeps ``put_config`` smart-diffing for callers that
# don't want to track which mutation they're doing (auto-balance,
# whitelist-front re-pushes, full re-syncs).
class InboundUserAddIn(BaseModel):
    tag: str
    protocol: str = "vless"
    # ``port`` is only used to make the temp ``adu`` config parseable
    # — xray-core's CLI requires every inbound entry to declare a port,
    # even though the runtime API matches by tag. Pass the live
    # inbound's real port so a stray validation never trips up.
    port: int = 0
    users: list[dict[str, Any]]


class InboundUserRemoveIn(BaseModel):
    tag: str
    emails: list[str]


class InboundUserOpOut(BaseModel):
    ok: bool
    added: int = 0
    removed: int = 0
    message: str = ""


@app.post(
    "/xray/inbound/users/add",
    response_model=InboundUserOpOut,
    dependencies=[Depends(require_token)],
)
def inbound_users_add(body: InboundUserAddIn) -> InboundUserOpOut:
    """Add users to a live inbound via ``xray api adu`` (no xray restart).

    The on-disk config.json is *not* modified — the caller is expected to
    keep the panel DB in sync and run a full ``put_config`` later if it
    wants the new account to survive a restart. (For the panel that's
    automatic: every subscription change re-pushes a fresh config
    eventually.)
    """
    if not body.users:
        return InboundUserOpOut(ok=True, added=0, message="no users")
    ok, added, msg = _xray_api_add_users(
        tag=body.tag, protocol=body.protocol, port=body.port, users=body.users,
    )
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=f"xray api adu failed: {msg}",
        )
    return InboundUserOpOut(ok=True, added=added, message=msg)


@app.post(
    "/xray/inbound/users/remove",
    response_model=InboundUserOpOut,
    dependencies=[Depends(require_token)],
)
def inbound_users_remove(body: InboundUserRemoveIn) -> InboundUserOpOut:
    """Remove users from a live inbound via ``xray api rmu`` (no xray restart).

    Same caveat as ``/xray/inbound/users/add``: on-disk config.json is
    untouched. Pair with a later ``put_config`` if you want the change
    to survive a restart.
    """
    if not body.emails:
        return InboundUserOpOut(ok=True, removed=0, message="no emails")
    ok, removed, msg = _xray_api_remove_users(tag=body.tag, emails=body.emails)
    if not ok:
        raise HTTPException(
            status_code=502,
            detail=f"xray api rmu failed: {msg}",
        )
    return InboundUserOpOut(ok=True, removed=removed, message=msg)


@app.get("/stats", response_model=StatsOut, dependencies=[Depends(require_token)])
def stats(reset: bool = False) -> StatsOut:
    """Return user + inbound traffic counters from xray's StatsService.

    Uses ``xray api statsquery`` which prints plain text lines ``stat: ... value: N``.
    ``reset=true`` resets counters after reading.
    """
    cmd = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API_ADDR}"]
    if reset:
        cmd.append("-reset")
    cmd.append("")
    r = _run(cmd, check=False, timeout=10)
    if r.returncode != 0:
        # If xray isn't reachable, return empty list rather than 500 so the panel
        # UI can still render.
        return StatsOut(stats=[])

    out: list[StatItem] = []
    # Output format (one "entry" per stat):
    #   stat: <
    #     name: "user>>>foo>>>traffic>>>uplink"
    #     value: 12345
    #   >
    # Parse loosely with regex.
    text = r.stdout or ""
    for m in re.finditer(
        r'name:\s*"([^"]+)"\s+value:\s*(-?\d+)',
        text,
    ):
        out.append(StatItem(name=m.group(1), value=int(m.group(2))))
    # Also accept JSON output if xray version emits it.
    if not out:
        try:
            j = json.loads(text)
            for s in j.get("stat", []) or []:
                out.append(StatItem(name=s.get("name", ""), value=int(s.get("value", 0) or 0)))
        except Exception:
            pass
    return StatsOut(stats=out)


def _read_proc(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _cpu_times() -> tuple[int, int]:
    """Return (idle, total) jiffies summed across all CPUs."""
    text = _read_proc("/proc/stat")
    for line in text.splitlines():
        if line.startswith("cpu "):
            parts = line.split()[1:]
            nums = [int(x) for x in parts[:10] if x.lstrip("-").isdigit()]
            if len(nums) >= 5:
                idle = nums[3] + (nums[4] if len(nums) > 4 else 0)  # idle + iowait
                total = sum(nums)
                return idle, total
    return 0, 0


_LAST_CPU: tuple[int, int] = (0, 0)
_CPU_LOCK = threading.Lock()


def _cpu_percent() -> float:
    global _LAST_CPU
    import time as _t

    # /sysinfo and the background live sampler may run concurrently.  Without
    # this lock both calls can consume the same baseline and intermittently
    # report 0% or a spike unrelated to the real CPU load.
    with _CPU_LOCK:
        idle1, total1 = _cpu_times()
        if _LAST_CPU == (0, 0):
            _t.sleep(0.15)
            idle2, total2 = _cpu_times()
        else:
            idle2, total2 = idle1, total1
            idle1, total1 = _LAST_CPU
        _LAST_CPU = (idle2, total2)
        d_total = total2 - total1
        d_idle = idle2 - idle1
        if d_total <= 0:
            return 0.0
        return round(max(0.0, min(100.0, (1.0 - d_idle / d_total) * 100.0)), 2)


def _meminfo() -> dict[str, int]:
    out: dict[str, int] = {}
    for line in _read_proc("/proc/meminfo").splitlines():
        k, _, rest = line.partition(":")
        v = rest.strip().split()
        if v and v[0].isdigit():
            # values are in kB
            out[k.strip()] = int(v[0]) * 1024
    return out


def _net_counters() -> tuple[int, int]:
    """Sum rx/tx bytes across all non-loopback interfaces."""
    rx = tx = 0
    text = _read_proc("/proc/net/dev")
    for line in text.splitlines()[2:]:
        if ":" not in line:
            continue
        name, _, rest = line.partition(":")
        name = name.strip()
        if name == "lo" or name.startswith(("docker", "br-", "veth")):
            continue
        parts = rest.split()
        if len(parts) >= 9:
            try:
                rx += int(parts[0])
                tx += int(parts[8])
            except ValueError:
                pass
    return rx, tx


def _collect_sysinfo(*, cpu_percent: float | None = None) -> dict[str, Any]:
    """Collect one coherent host snapshot.

    ``cpu_percent`` can be supplied by the live sampler so the same sample is
    used for both its compact response and the expanded host fields.
    """
    mem = _meminfo()
    mem_total = mem.get("MemTotal", 0)
    mem_available = mem.get("MemAvailable", 0)
    mem_used = max(0, mem_total - mem_available)
    swap_total = mem.get("SwapTotal", 0)
    swap_free = mem.get("SwapFree", 0)
    swap_used = max(0, swap_total - swap_free)

    # load avg from /proc/loadavg
    try:
        la = _read_proc("/proc/loadavg").split()
        load_1, load_5, load_15 = float(la[0]), float(la[1]), float(la[2])
    except (ValueError, IndexError):
        load_1 = load_5 = load_15 = 0.0

    # uptime
    try:
        uptime = int(float(_read_proc("/proc/uptime").split()[0]))
    except (ValueError, IndexError):
        uptime = 0

    # disk usage on /
    try:
        st = os.statvfs("/")
        disk_total = st.f_blocks * st.f_frsize
        disk_used = (st.f_blocks - st.f_bfree) * st.f_frsize
    except OSError:
        disk_total = disk_used = 0

    rx, tx = _net_counters()

    kernel = ""
    try:
        kernel = os.uname().release
    except OSError:
        pass
    hostname = ""
    try:
        hostname = os.uname().nodename
    except OSError:
        pass

    return {
        "cpu_percent": _cpu_percent() if cpu_percent is None else cpu_percent,
        "cpu_count": os.cpu_count() or 1,
        "load_1": load_1,
        "load_5": load_5,
        "load_15": load_15,
        "mem_total": mem_total,
        "mem_used": mem_used,
        "mem_available": mem_available,
        "swap_total": swap_total,
        "swap_used": swap_used,
        "disk_total": disk_total,
        "disk_used": disk_used,
        "uptime_seconds": uptime,
        "net_rx_bytes": rx,
        "net_tx_bytes": tx,
        "kernel": kernel,
        "hostname": hostname,
    }


@app.get("/sysinfo", response_model=SysInfoOut, dependencies=[Depends(require_token)])
def sysinfo() -> SysInfoOut:
    return SysInfoOut(**_collect_sysinfo())


# ---------- live sessions + throughput ----------
#
# ``/live`` answers two questions the per-node card on the dashboard needs:
#
#   1. *How many clients are connected right now?*
#   2. *How fast is the network going (MB/s) right now, in total and per
#      client?*
#
# xray's StatsService exposes only monotonic byte counters per user (and
# per inbound); it does NOT expose "active connection count" directly.
# The closest signal we have is "did this client's uplink/downlink
# counter move since the last sample?". So we keep a small in-process
# snapshot of the last seen counters per email plus the timestamp of the
# last time each client moved any traffic, and derive:
#
#   * ``online_clients`` — count of emails whose counters moved at least
#     once within ``online_window_s`` (default 90 s). A connected-but-idle
#     client (open socket, no traffic) still shows up for ~90 s after its
#     last packet, which matches how admins actually think about "online".
#   * ``net_rx_bps`` / ``net_tx_bps`` — host NIC rate (bytes/s) computed
#     from the delta of /proc/net/dev between consecutive samples.
#   * ``clients[].up_bps`` / ``down_bps`` — per-client rate over the same
#     interval.
#
# The first call after agent start has nothing to diff against, so it
# seeds the snapshot and returns ``online_clients=0`` with empty rates.
# The panel polls every few seconds, so useful numbers appear within one
# poll interval.
_LIVE_WINDOW_DEFAULT = 120.0


class _LiveSnapshot:
    __slots__ = (
        "ts", "sampled_at", "sample_window_s", "stats", "net",
        "last_active", "rates", "net_rx_bps", "net_tx_bps", "sysinfo",
    )

    def __init__(self) -> None:
        self.ts: float = 0.0
        self.sampled_at: float = 0.0
        self.sample_window_s: float = 0.0
        self.stats: dict[str, dict[str, int]] = {}
        self.net: tuple[int, int] = (0, 0)
        self.last_active: dict[str, float] = {}
        self.rates: dict[str, dict[str, int]] = {}
        self.net_rx_bps: int = 0
        self.net_tx_bps: int = 0
        self.sysinfo: dict[str, Any] = {}


_live_snapshot = _LiveSnapshot()
_live_lock = threading.Lock()


class LiveClientOut(BaseModel):
    email: str
    online: bool
    up_bps: int = 0
    down_bps: int = 0


class LiveOut(BaseModel):
    online_clients: int
    online_emails: list[str]
    sample_window_s: float
    online_window_s: float
    net_rx_bps: int
    net_tx_bps: int
    cpu_percent: float
    cpu_count: int = 1
    load_1: float = 0.0
    load_5: float = 0.0
    load_15: float = 0.0
    mem_total: int = 0
    mem_used: int = 0
    disk_total: int = 0
    disk_used: int = 0
    uptime_seconds: int = 0
    clients: list[LiveClientOut]
    ts: float
    sampled_at: float = 0.0
    sample_age_s: float = 0.0


def _collect_user_stats() -> dict[str, dict[str, int]] | None:
    """Pull cumulative user counters, distinguishing failure from no users."""
    cmd = [XRAY_BIN, "api", "statsquery", f"--server={XRAY_API_ADDR}", ""]
    try:
        r = _run(cmd, check=False, timeout=8)
    except Exception:  # noqa: BLE001
        return None
    if r.returncode != 0:
        return None
    out: dict[str, dict[str, int]] = {}
    text = r.stdout or ""
    for match in re.finditer(r'name:\s*"([^"]+)"\s+value:\s*(-?\d+)', text):
        name = match.group(1)
        value = int(match.group(2))
        if name.startswith("user>>>") and ">>>traffic>>>" in name:
            email = name.split(">>>", 2)[1]
            direction = name.rsplit(">>>", 1)[-1]
            bucket = out.setdefault(email, {"up": 0, "down": 0})
            if direction == "uplink":
                bucket["up"] += max(0, value)
            elif direction == "downlink":
                bucket["down"] += max(0, value)
    if not out:
        try:
            payload = json.loads(text)
            for item in payload.get("stat", []) or []:
                name = item.get("name", "")
                value = int(item.get("value", 0) or 0)
                if name.startswith("user>>>") and ">>>traffic>>>" in name:
                    email = name.split(">>>", 2)[1]
                    direction = name.rsplit(">>>", 1)[-1]
                    bucket = out.setdefault(email, {"up": 0, "down": 0})
                    if direction == "uplink":
                        bucket["up"] += max(0, value)
                    elif direction == "downlink":
                        bucket["down"] += max(0, value)
        except Exception:  # noqa: BLE001
            pass
    return out


def _counter_delta(current: int, previous: int) -> int:
    return current - previous if current >= previous else current


def _sample_live_once() -> None:
    """Refresh telemetry independently of dashboard request timing."""
    now = time.monotonic()
    sampled_at = time.time()
    current_stats = _collect_user_stats()
    current_net = _net_counters()
    cpu = _cpu_percent()
    host = _collect_sysinfo(cpu_percent=cpu)

    with _live_lock:
        previous_ts = _live_snapshot.ts
        previous_stats = _live_snapshot.stats
        previous_net = _live_snapshot.net
        last_active = _live_snapshot.last_active
        dt = now - previous_ts if previous_ts > 0 else 0.0
        stats_ok = current_stats is not None
        if current_stats is None:
            current_stats = previous_stats

        rates: dict[str, dict[str, int]] = {}
        for email in set(current_stats) | set(previous_stats) | set(last_active):
            current = current_stats.get(email, {"up": 0, "down": 0})
            previous = previous_stats.get(email, {"up": 0, "down": 0})
            d_up = _counter_delta(current["up"], previous["up"]) if stats_ok else 0
            d_down = _counter_delta(current["down"], previous["down"]) if stats_ok else 0
            if d_up > 0 or d_down > 0:
                last_active[email] = now
            rates[email] = {
                "up_bps": int(d_up / dt) if dt > 0 else 0,
                "down_bps": int(d_down / dt) if dt > 0 else 0,
            }

        for email in [e for e, active_at in last_active.items() if active_at < now - 1200]:
            last_active.pop(email, None)
            if email not in current_stats:
                rates.pop(email, None)

        net_rx_bps = 0
        net_tx_bps = 0
        if dt > 0:
            net_rx_bps = int(_counter_delta(current_net[0], previous_net[0]) / dt)
            net_tx_bps = int(_counter_delta(current_net[1], previous_net[1]) / dt)

        _live_snapshot.ts = now
        _live_snapshot.sampled_at = sampled_at
        _live_snapshot.sample_window_s = dt
        _live_snapshot.stats = current_stats
        _live_snapshot.net = current_net
        _live_snapshot.rates = rates
        _live_snapshot.net_rx_bps = max(0, net_rx_bps)
        _live_snapshot.net_tx_bps = max(0, net_tx_bps)
        _live_snapshot.sysinfo = host


_live_sampler_stop = threading.Event()
_live_sampler_thread: threading.Thread | None = None


def _live_sampler_loop() -> None:
    while not _live_sampler_stop.is_set():
        started = time.monotonic()
        try:
            _sample_live_once()
        except Exception:  # noqa: BLE001
            log.exception("live sampler failed")
        _live_sampler_stop.wait(
            max(0.2, LIVE_SAMPLE_INTERVAL_S - (time.monotonic() - started))
        )


def _start_live_sampler() -> None:
    global _live_sampler_thread
    if _live_sampler_thread is not None and _live_sampler_thread.is_alive():
        return
    _live_sampler_stop.clear()
    _live_sampler_thread = threading.Thread(
        target=_live_sampler_loop, name="xray-live-sampler", daemon=True
    )
    _live_sampler_thread.start()


@app.on_event("startup")
def _agent_startup() -> None:
    _start_live_sampler()


@app.on_event("shutdown")
def _agent_shutdown() -> None:
    _live_sampler_stop.set()
    if _live_sampler_thread is not None:
        _live_sampler_thread.join(timeout=2.0)


@app.get("/live", response_model=LiveOut, dependencies=[Depends(require_token)])
def live(online_window: float = _LIVE_WINDOW_DEFAULT) -> LiveOut:
    """Return the latest fixed-cadence live snapshot without running xray CLI."""
    window = float(max(5.0, min(600.0, online_window)))
    _start_live_sampler()
    if _live_snapshot.ts <= 0:
        _sample_live_once()

    now = time.monotonic()
    with _live_lock:
        stats = dict(_live_snapshot.stats)
        rates = {email: dict(value) for email, value in _live_snapshot.rates.items()}
        last_active = dict(_live_snapshot.last_active)
        sample_window = _live_snapshot.sample_window_s
        net_rx_bps = _live_snapshot.net_rx_bps
        net_tx_bps = _live_snapshot.net_tx_bps
        host = dict(_live_snapshot.sysinfo)
        sampled_at = _live_snapshot.sampled_at

    online_emails = sorted(
        email for email, active_at in last_active.items()
        if email in stats and now - active_at <= window
    )
    online_set = set(online_emails)
    clients_out = [
        LiveClientOut(
            email=email,
            online=email in online_set,
            up_bps=int(rates.get(email, {}).get("up_bps", 0) or 0),
            down_bps=int(rates.get(email, {}).get("down_bps", 0) or 0),
        )
        for email in sorted(stats)
    ]

    return LiveOut(
        online_clients=len(online_emails),
        online_emails=online_emails,
        sample_window_s=round(sample_window, 2),
        online_window_s=window,
        net_rx_bps=net_rx_bps,
        net_tx_bps=net_tx_bps,
        cpu_percent=float(host.get("cpu_percent", 0.0) or 0.0),
        cpu_count=int(host.get("cpu_count", 1) or 1),
        load_1=float(host.get("load_1", 0.0) or 0.0),
        load_5=float(host.get("load_5", 0.0) or 0.0),
        load_15=float(host.get("load_15", 0.0) or 0.0),
        mem_total=int(host.get("mem_total", 0) or 0),
        mem_used=int(host.get("mem_used", 0) or 0),
        disk_total=int(host.get("disk_total", 0) or 0),
        disk_used=int(host.get("disk_used", 0) or 0),
        uptime_seconds=int(host.get("uptime_seconds", 0) or 0),
        clients=clients_out,
        ts=sampled_at,
        sampled_at=sampled_at,
        sample_age_s=round(max(0.0, time.time() - sampled_at), 2),
    )


def _public_key_from_private(private_key: str) -> str:
    """Ask the installed xray binary to derive a Reality public key."""
    if not private_key:
        return ""
    try:
        result = _run(
            [XRAY_BIN, "x25519", "-i", private_key], check=False, timeout=10
        )
    except Exception:  # noqa: BLE001
        return ""
    if result.returncode != 0:
        return ""
    for line in (result.stdout or "").splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip().lower() in {"publickey", "public key", "password"}:
            return value.strip()
    return ""


@app.get("/xray/inbounds", dependencies=[Depends(require_token)])
def inspect_inbounds() -> dict[str, Any]:
    """Return non-secret metadata for importable VLESS+Reality inbounds."""
    config = _read_current_config()
    if config is None:
        raise HTTPException(status_code=404, detail="xray config.json is unavailable")
    out: list[dict[str, Any]] = []
    public_keys: dict[str, str] = {}
    for inbound in config.get("inbounds") or []:
        if str(inbound.get("protocol") or "").lower() != "vless":
            continue
        tag = str(inbound.get("tag") or "").strip()
        if not tag:
            continue
        stream = inbound.get("streamSettings") or {}
        reality = stream.get("realitySettings") or {}
        if str(stream.get("security") or "").lower() != "reality" or not reality:
            continue
        private_key = str(reality.get("privateKey") or "")
        if private_key not in public_keys:
            public_keys[private_key] = _public_key_from_private(private_key)
        network = str(stream.get("network") or "tcp").lower()
        transport_path = ""
        if network == "grpc":
            transport_path = str((stream.get("grpcSettings") or {}).get("serviceName") or "")
        elif network == "xhttp":
            transport_path = str((stream.get("xhttpSettings") or {}).get("path") or "")
        clients = (inbound.get("settings") or {}).get("clients") or []
        out.append(
            {
                "tag": tag,
                "protocol": "vless",
                "port": int(inbound.get("port") or 0),
                "listen": str(inbound.get("listen") or ""),
                "security": "reality",
                "server_names": [str(v) for v in reality.get("serverNames") or [] if v],
                "dest": str(reality.get("dest") or reality.get("target") or ""),
                "short_ids": [str(v) for v in reality.get("shortIds") or [] if v],
                "public_key": public_keys.get(private_key, ""),
                "transport": network,
                "transport_path": transport_path,
                "client_count": len(clients),
            }
        )
    return {"inbounds": out}


# ---------- native WARP ----------
_warp_install_lock = threading.Lock()


def _warp_status() -> WarpStatusOut:
    service_active = False
    interface_active = False
    try:
        service_active = _systemctl_active(WARP_SERVICE)
    except Exception:  # noqa: BLE001
        pass
    try:
        link = _run(
            ["ip", "link", "show", "dev", "warp"], check=False, timeout=8
        )
        interface_active = link.returncode == 0
    except Exception:  # noqa: BLE001
        pass

    warp_ip = ""
    account = ""
    reachable = False
    message = ""
    if interface_active and shutil.which("curl"):
        try:
            ip_result = _run(
                [
                    "curl", "--interface", "warp", "-4", "-fsS",
                    "--max-time", "15", "https://ifconfig.me/ip",
                ],
                check=False,
                timeout=20,
            )
            if ip_result.returncode == 0:
                warp_ip = (ip_result.stdout or "").strip().splitlines()[0]
            trace = _run(
                [
                    "curl", "--interface", "warp", "-4", "-fsS",
                    "--max-time", "15",
                    "https://www.cloudflare.com/cdn-cgi/trace",
                ],
                check=False,
                timeout=20,
            )
            for line in (trace.stdout or "").splitlines():
                key, sep, value = line.partition("=")
                if sep and key == "warp":
                    account = value.strip().lower()
            try:
                ipaddress.ip_address(warp_ip)
                reachable = True
            except ValueError:
                reachable = False
            if reachable and account not in {"on", "plus"}:
                # warp-native itself documents that the trace endpoint may not
                # confirm warp=on even though interface-bound egress works.
                message = "interface-bound egress works; Cloudflare trace was inconclusive"
            elif not reachable:
                message = "WARP interface exists but interface-bound egress failed"
        except Exception as exc:  # noqa: BLE001
            message = f"WARP connectivity check failed: {exc}"
    elif interface_active:
        message = "curl is unavailable, WARP connectivity was not verified"

    return WarpStatusOut(
        installed=WARP_CONFIG.exists(),
        service_active=service_active,
        interface_active=interface_active,
        reachable=reachable,
        warp_ip=warp_ip,
        account=account,
        message=message,
    )


@app.get(
    "/warp/status",
    response_model=WarpStatusOut,
    dependencies=[Depends(require_token)],
)
def warp_status() -> WarpStatusOut:
    return _warp_status()


@app.post(
    "/warp/install",
    response_model=WarpStatusOut,
    dependencies=[Depends(require_token)],
)
def warp_install(body: WarpInstallIn) -> WarpStatusOut:
    """Install distillium/warp-native via stdin-driven prompts and verify it."""
    if os.geteuid() != 0:
        raise HTTPException(status_code=503, detail="WARP installation requires root")
    license_key = (body.license_key or "").strip()
    if len(license_key) > 256 or "\n" in license_key or "\r" in license_key:
        raise HTTPException(status_code=400, detail="invalid WARP+ license key")

    with _warp_install_lock:
        before = _warp_status()
        if before.reachable:
            return before

        # A previous installation may simply be stopped. Avoid re-registering
        # the Cloudflare account in that case.
        if WARP_CONFIG.exists():
            enable = _run(
                ["systemctl", "enable", "--now", WARP_SERVICE],
                check=False,
                timeout=45,
            )
            after = _warp_status()
            if after.reachable:
                return after
            detail = (enable.stderr or enable.stdout or after.message).strip()
            raise HTTPException(
                status_code=502,
                detail=f"could not activate existing WARP interface: {detail}",
            )

        script_path = ""
        try:
            request = urllib.request.Request(
                WARP_INSTALL_URL,
                headers={"User-Agent": "xnPanel-agent/1.0"},
            )
            with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310
                script = response.read(2_000_001)
            if len(script) > 2_000_000 or not script.startswith(b"#!/bin/bash"):
                raise ValueError("unexpected warp-native install script")
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix="warp-native-", suffix=".sh", delete=False
            ) as handle:
                handle.write(script)
                script_path = handle.name
            run = subprocess.run(
                ["bash", script_path],
                input=f"1\n{license_key}\n2\n",
                capture_output=True,
                text=True,
                check=False,
                timeout=900,
            )
        except subprocess.TimeoutExpired as exc:
            raise HTTPException(
                status_code=504, detail="warp-native installation timed out"
            ) from exc
        except HTTPException:
            raise
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=502, detail=f"could not download/run warp-native: {exc}"
            ) from exc
        finally:
            if script_path:
                Path(script_path).unlink(missing_ok=True)

        if run.returncode != 0:
            output = "\n".join(
                (run.stderr or run.stdout or "warp-native failed").splitlines()[-20:]
            )
            if license_key:
                output = output.replace(license_key, "<redacted>")
            raise HTTPException(
                status_code=502,
                detail=f"warp-native exited with {run.returncode}: {output}",
            )

        _run(
            ["systemctl", "enable", "--now", WARP_SERVICE],
            check=False,
            timeout=45,
        )
        after = _warp_status()
        if not after.reachable:
            raise HTTPException(
                status_code=502,
                detail=after.message or "WARP installed but egress verification failed",
            )
        return after


class SpeedTestOut(BaseModel):
    provider: str
    download_mbps: float
    upload_mbps: float
    latency_ms: float
    download_bytes: int
    upload_bytes: int
    tested_at: datetime


_speedtest_lock = threading.Lock()


def _speed_url(base: str, byte_count: int) -> str:
    query = urllib.parse.urlencode(
        {"bytes": byte_count, "_": f"{time.time_ns()}"}
    )
    return f"{base}{'&' if '?' in base else '?'}{query}"


def _download_probe(byte_count: int) -> tuple[int, float]:
    request = urllib.request.Request(
        _speed_url(SPEEDTEST_DOWNLOAD_URL, byte_count),
        headers={"User-Agent": "xnPanel-agent/1.0", "Cache-Control": "no-cache"},
    )
    started = time.perf_counter()
    received = 0
    with urllib.request.urlopen(request, timeout=35) as response:
        while True:
            chunk = response.read(256 * 1024)
            if not chunk:
                break
            received += len(chunk)
    return received, max(0.001, time.perf_counter() - started)


def _upload_probe(byte_count: int) -> tuple[int, float]:
    body = b"0" * byte_count
    request = urllib.request.Request(
        SPEEDTEST_UPLOAD_URL,
        data=body,
        method="POST",
        headers={
            "User-Agent": "xnPanel-agent/1.0",
            "Content-Type": "application/octet-stream",
            "Cache-Control": "no-cache",
        },
    )
    started = time.perf_counter()
    with urllib.request.urlopen(request, timeout=35) as response:
        response.read()
    return len(body), max(0.001, time.perf_counter() - started)


@app.post("/speedtest", response_model=SpeedTestOut, dependencies=[Depends(require_token)])
def run_speedtest() -> SpeedTestOut:
    """Run one bounded test against Cloudflare's public speed endpoints."""
    if not _speedtest_lock.acquire(blocking=False):
        raise HTTPException(status_code=409, detail="a speed test is already running")
    try:
        latency_samples: list[float] = []
        for _ in range(3):
            started = time.perf_counter()
            received, _elapsed = _download_probe(0)
            del received, _elapsed
            latency_samples.append((time.perf_counter() - started) * 1000.0)
        downloaded, download_s = _download_probe(SPEEDTEST_DOWNLOAD_BYTES)
        uploaded, upload_s = _upload_probe(SPEEDTEST_UPLOAD_BYTES)
        return SpeedTestOut(
            provider="Cloudflare",
            download_mbps=round((downloaded * 8) / download_s / 1_000_000, 2),
            upload_mbps=round((uploaded * 8) / upload_s / 1_000_000, 2),
            latency_ms=round(float(median(latency_samples)), 2),
            download_bytes=downloaded,
            upload_bytes=uploaded,
            tested_at=datetime.now(timezone.utc),
        )
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=502, detail=f"speed test failed: {exc}") from exc
    finally:
        _speedtest_lock.release()


@app.post("/keys", response_model=KeyPairOut, dependencies=[Depends(require_token)])
def keys() -> KeyPairOut:
    r = _run([XRAY_BIN, "x25519"], check=False, timeout=10)
    if r.returncode != 0:
        raise HTTPException(status_code=500, detail=r.stderr.strip() or "x25519 failed")
    priv = pub = ""
    for line in (r.stdout or "").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            k = k.strip().lower()
            v = v.strip()
            if "private" in k:
                priv = v
            elif "public" in k or "password" in k:
                pub = v
    if not priv or not pub:
        raise HTTPException(status_code=500, detail="could not parse x25519 output")
    return KeyPairOut(private_key=priv, public_key=pub)


# ---------- xray lifecycle ----------
class XrayActionOut(BaseModel):
    ok: bool
    action: str
    xray_active: bool
    xray_version: str = ""
    stderr: str = ""


class XrayLogsOut(BaseModel):
    lines: list[str]


def _systemctl(action: str, service: str = XRAY_SERVICE) -> subprocess.CompletedProcess[str]:
    return _run(["systemctl", action, service], check=False, timeout=30)


@app.post("/xray/restart", response_model=XrayActionOut, dependencies=[Depends(require_token)])
def xray_restart() -> XrayActionOut:
    r = _systemctl("restart")
    return XrayActionOut(
        ok=r.returncode == 0,
        action="restart",
        xray_active=_systemctl_active(XRAY_SERVICE),
        xray_version=_xray_version(),
        stderr=(r.stderr or "").strip(),
    )


@app.post("/xray/start", response_model=XrayActionOut, dependencies=[Depends(require_token)])
def xray_start() -> XrayActionOut:
    r = _systemctl("start")
    return XrayActionOut(
        ok=r.returncode == 0,
        action="start",
        xray_active=_systemctl_active(XRAY_SERVICE),
        xray_version=_xray_version(),
        stderr=(r.stderr or "").strip(),
    )


@app.post("/xray/stop", response_model=XrayActionOut, dependencies=[Depends(require_token)])
def xray_stop() -> XrayActionOut:
    r = _systemctl("stop")
    return XrayActionOut(
        ok=r.returncode == 0,
        action="stop",
        xray_active=_systemctl_active(XRAY_SERVICE),
        xray_version=_xray_version(),
        stderr=(r.stderr or "").strip(),
    )


@app.get("/xray/logs", response_model=XrayLogsOut, dependencies=[Depends(require_token)])
def xray_logs(lines: int = 200) -> XrayLogsOut:
    """Return the last ``lines`` lines from the xray journal (bounded 1..2000)."""
    n = max(1, min(2000, int(lines)))
    r = _run(
        ["journalctl", "-u", XRAY_SERVICE, "--no-pager", "-n", str(n)],
        check=False,
        timeout=15,
    )
    text = r.stdout or ""
    return XrayLogsOut(lines=text.splitlines())


class RebootIn(BaseModel):
    delay_seconds: int = 3


class RebootOut(BaseModel):
    ok: bool
    scheduled: bool
    message: str = ""


class VersionOut(BaseModel):
    """Snapshot of the xnpanel CLI version state on this host.

    Mirrors the fields ``xnpanel`` writes into
    ``/var/lib/xnpanel/update-available`` (an env-style cache populated by
    ``xnpanel check``). The panel uses this to display per-node version
    badges and decide whether to offer "update available" UI.
    """

    cli_present: bool = False
    installed: str = ""
    latest: str = ""
    branch: str = ""
    status: str = ""           # "uptodate" | "available" | "unknown"
    checked_at: str = ""


class UpgradeOut(BaseModel):
    ok: bool
    scheduled: bool
    message: str = ""


XNPANEL_BIN = os.environ.get("XNPANEL_BIN", "/usr/local/bin/xnpanel")
XNPANEL_CACHE = Path(
    os.environ.get("XNPANEL_CACHE", "/var/lib/xnpanel/update-available")
)
XNPANEL_VERSION_FILE = Path(
    os.environ.get("XNPANEL_VERSION_FILE", "/etc/xnpanel/version")
)


def _xnpanel_present() -> bool:
    return Path(XNPANEL_BIN).is_file() and os.access(XNPANEL_BIN, os.X_OK)


def _read_envfile(path: Path) -> dict[str, str]:
    """Parse a trivial ``KEY=value\\n`` file. Empty/missing → empty dict."""
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip()
    except FileNotFoundError:
        return {}
    except Exception:  # noqa: BLE001 — best-effort cache parse
        return {}
    return out


@app.get("/system/version", response_model=VersionOut, dependencies=[Depends(require_token)])
def system_version() -> VersionOut:
    """Return what `xnpanel check` last wrote to the update-available cache.

    We do NOT call ``xnpanel check`` here — that would hit GitHub on every
    panel poll. The systemd timer (xnpanel-update-check.timer) refreshes
    this file; the panel just reads the snapshot.
    """
    cli = _xnpanel_present()
    cache = _read_envfile(XNPANEL_CACHE)
    installed = cache.get("CURRENT", "")
    branch = cache.get("BRANCH", "")
    if not installed:
        # Fall back to the version file written by install.sh /
        # ``xnpanel update`` if the update-available cache hasn't been
        # populated yet (fresh node, ``xnpanel-update-check.timer``
        # fires ~2 min after boot — until then the cache is missing).
        # The version file is env-style (``COMMIT=<sha>\nBRANCH=...``),
        # not a bare SHA, so we parse it the same way the cache is
        # parsed; reading it as a single string would yield the whole
        # multi-line blob and break the panel's "installed" badge.
        version_file = _read_envfile(XNPANEL_VERSION_FILE)
        installed = version_file.get("COMMIT", "")
        if not branch:
            branch = version_file.get("BRANCH", "")
    return VersionOut(
        cli_present=cli,
        installed=installed,
        latest=cache.get("LATEST", ""),
        branch=branch,
        status=cache.get("STATUS", ""),
        checked_at=cache.get("CHECKED_AT", ""),
    )


@app.post("/system/upgrade", response_model=UpgradeOut, dependencies=[Depends(require_token)])
def system_upgrade() -> UpgradeOut:
    """Run ``xnpanel update`` in the background and return immediately.

    Mirrors the same trick as ``/system/reboot``: ``xnpanel update``
    restarts ``xray-agent.service`` (and on the panel host also
    ``xray-panel.service``). If we waited synchronously the agent would
    kill its own HTTP worker mid-response. Detach a process whose stdio
    is fully redirected and let it run after we reply.

    The panel polls ``/system/version`` afterwards to confirm the new
    SHA was installed.
    """
    if not _xnpanel_present():
        return UpgradeOut(
            ok=False,
            scheduled=False,
            message=(
                f"xnpanel CLI not installed at {XNPANEL_BIN}. "
                "Re-run install.sh on this node to install it."
            ),
        )
    try:
        # Small delay so the HTTP response flushes to the panel before
        # the agent restarts itself.
        #
        # We pipe stdout/stderr through ``logger -t xnpanel-upgrade`` so
        # the run lands in journalctl. Previously this was redirected to
        # /dev/null and a silently-failing ``xnpanel update --force`` (git
        # blocked, dirty tree, …) was invisible to admins — the panel
        # would happily show ``scheduled=ok`` while the node never picked
        # up the new commit. ``logger`` is part of bsdutils / util-linux,
        # always present on Debian/Ubuntu/RHEL hosts where this agent
        # runs. If it's missing we still fall back to /dev/null so the
        # upgrade itself isn't blocked.
        upgrade_cmd = (
            f"sleep 2 && ({XNPANEL_BIN} update --force 2>&1 "
            "| logger -t xnpanel-upgrade || true)"
        )
        subprocess.Popen(  # noqa: S603,S607 — controlled args, no shell
            ["bash", "-c", upgrade_cmd],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception as exc:  # noqa: BLE001
        return UpgradeOut(
            ok=False, scheduled=False,
            message=f"could not schedule upgrade: {exc}",
        )
    return UpgradeOut(
        ok=True, scheduled=True,
        message="xnpanel update scheduled (services will restart shortly)",
    )


@app.post("/system/reboot", response_model=RebootOut, dependencies=[Depends(require_token)])
def system_reboot(body: RebootIn | None = None) -> RebootOut:
    """Schedule a host reboot after a short delay.

    We can't call ``systemctl reboot`` synchronously because it kills the HTTP
    response before the client sees it. We also can't rely on ``shutdown -r +1``
    alone — on some distros ``shutdown`` leaves the node in a "scheduled" state
    where the reboot never fires if the scheduler process is killed. Instead
    we double up: schedule ``shutdown -r +1`` as a best-effort announcement to
    logged-in users, then also detach a background ``sleep N && systemctl
    reboot --force`` that is immune to the current HTTP worker dying.
    """
    delay = 5 if body is None else max(2, int(body.delay_seconds))
    # Best-effort wall announcement; ignore failures (not all distros ship
    # `shutdown`, and non-fatal errors shouldn't block the reboot).
    try:
        _run(
            ["shutdown", "-r", "+1", "xray-panel agent requested reboot"],
            check=False, timeout=5,
        )
    except Exception:  # noqa: BLE001 — truly best-effort
        pass

    # Detach: the process keeps running after this HTTP worker exits, and its
    # stdio is fully redirected so uvicorn doesn't track it as a child.
    # `systemctl reboot --force` bypasses the inhibit lock and a hanging
    # unit — we've already confirmed the user's intent via the panel prompt.
    try:
        subprocess.Popen(  # noqa: S603,S607 — controlled args, no shell
            ["bash", "-c", f"sleep {delay} && systemctl reboot --force"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
            close_fds=True,
        )
    except Exception as exc:  # noqa: BLE001
        return RebootOut(ok=False, scheduled=False, message=f"could not schedule reboot: {exc}")
    return RebootOut(
        ok=True, scheduled=True,
        message=f"reboot scheduled in ~{delay}s (systemctl reboot --force)",
    )

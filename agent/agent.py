"""xray-panel node agent.

Runs on each xray server. Exposes an HTTP API the central panel talks to:

* ``GET  /health``                   — liveness / xray version
* ``GET  /stats``                    — traffic counters from xray's StatsService
* ``GET  /sysinfo``                  — host metrics: cpu, memory, disk, load, uptime, net
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
import json
import logging
import os
import re
import secrets as _secrets
import shutil
import subprocess
import tempfile
from pathlib import Path
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


def _cpu_percent() -> float:
    global _LAST_CPU
    import time as _t

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


@app.get("/sysinfo", response_model=SysInfoOut, dependencies=[Depends(require_token)])
def sysinfo() -> SysInfoOut:
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

    return SysInfoOut(
        cpu_percent=_cpu_percent(),
        cpu_count=os.cpu_count() or 1,
        load_1=load_1,
        load_5=load_5,
        load_15=load_15,
        mem_total=mem_total,
        mem_used=mem_used,
        mem_available=mem_available,
        swap_total=swap_total,
        swap_used=swap_used,
        disk_total=disk_total,
        disk_used=disk_used,
        uptime_seconds=uptime,
        net_rx_bytes=rx,
        net_tx_bytes=tx,
        kernel=kernel,
        hostname=hostname,
    )


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
            elif "public" in k:
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

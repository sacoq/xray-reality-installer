"""xray-panel node agent.

Runs on each xray server. Exposes an HTTP API the central panel talks to:

* ``GET  /health``            — liveness / xray version
* ``GET  /stats``             — traffic counters from xray's StatsService
* ``GET  /sysinfo``           — host metrics: cpu, memory, disk, load, uptime, net
* ``GET  /config``            — current config.json
* ``POST /config``            — accept a new config.json, write + restart xray
* ``POST /keys``              — generate a fresh x25519 keypair (convenience)
* ``POST /xray/restart``      — systemctl restart xray
* ``POST /xray/start``        — systemctl start xray
* ``POST /xray/stop``         — systemctl stop xray
* ``GET  /xray/logs``         — last N lines from the xray journal
* ``POST /system/reboot``     — schedule a host reboot (shutdown -r +1)

All endpoints (except ``/health``) require ``Authorization: Bearer <token>``.
The token is provisioned by the installer and stored in ``/etc/xray-agent/agent.env``.
"""
from __future__ import annotations

import json
import os
import re
import secrets as _secrets
import shutil
import subprocess
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel


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


# ---------- schemas ----------
class HealthOut(BaseModel):
    ok: bool
    xray_version: str
    xray_active: bool


class ConfigIn(BaseModel):
    config: dict[str, Any]


class ConfigOut(BaseModel):
    config: dict[str, Any]


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
    payload = json.dumps(body.config, indent=2, ensure_ascii=False)

    # Validate via `xray -test` before we overwrite anything.
    tmp = XRAY_CONFIG.with_suffix(".new.json")
    _atomic_write(tmp, payload, mode=0o644)
    r = _run([XRAY_BIN, "-test", "-config", str(tmp)], check=False, timeout=20)
    if r.returncode != 0:
        tmp.unlink(missing_ok=True)
        raise HTTPException(
            status_code=400,
            detail=f"xray -test rejected config: {r.stderr.strip() or r.stdout.strip()}",
        )

    tmp.replace(XRAY_CONFIG)
    _run(["systemctl", "restart", XRAY_SERVICE], check=False, timeout=20)
    return ConfigOut(config=body.config)


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

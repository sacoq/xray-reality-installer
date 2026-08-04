"""Fleet telemetry, history roll-ups and scheduled node speed tests."""
from __future__ import annotations

import asyncio
import logging
import os
import socket
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone
from typing import Any, Optional
from urllib.parse import urlsplit

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from .agent_client import AgentClient
from .database import SessionLocal
from .models import (
    Client,
    Server,
    ServerMetricDaily,
    ServerMetricSample,
    ServerSpeedTest,
)
from .xray_push import BYPASS_CLIENT_LABEL, BALANCER_CLIENT_LABEL


log = logging.getLogger(__name__)


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name, "") or str(default)).strip())
    except ValueError:
        log.warning("invalid env %s, using %s", name, default)
        return default


METRICS_INTERVAL_S = max(15, _env_int("METRICS_INTERVAL_S", 60))
SPEEDTEST_INTERVAL_S = max(300, _env_int("SPEEDTEST_INTERVAL_S", 40 * 60))
RAW_RETENTION_DAYS = max(1, _env_int("METRICS_RAW_RETENTION_DAYS", 31))
AGENT_TIMEOUT_S = max(3, _env_int("METRICS_AGENT_TIMEOUT_S", 12))
PROBE_TIMEOUT_S = min(4.0, max(1.0, float(os.environ.get("METRICS_PROBE_TIMEOUT_S", "2.5"))))

FAILURE_KINDS = ("xray", "network", "node", "agent", "unknown")


def _endpoint(host_or_url: str, default_port: int) -> tuple[str, int] | None:
    """Extract a TCP endpoint from a URL/host without performing DNS work."""
    raw = (host_or_url or "").strip()
    if not raw:
        return None
    parsed = urlsplit(raw if "://" in raw else f"//{raw}")
    host = (parsed.hostname or "").strip()
    if not host:
        return None
    try:
        port = int(parsed.port or default_port)
    except ValueError:
        return None
    return host, port


def _tcp_reachable(host_or_url: str, default_port: int) -> tuple[bool, str]:
    endpoint = _endpoint(host_or_url, default_port)
    if endpoint is None:
        return False, "invalid endpoint"
    host, port = endpoint
    try:
        with socket.create_connection((host, port), timeout=PROBE_TIMEOUT_S):
            return True, ""
    except socket.gaierror as exc:
        return False, f"dns: {exc}"
    except OSError as exc:
        return False, f"tcp {host}:{port}: {exc}"


def _service_name(server: Server) -> str:
    protocol = (getattr(server, "protocol", "") or "").strip().lower()
    return "hysteria" if protocol in {"hysteria", "hysteria2"} else "xray"


def _failure_bucket(kind: str) -> str:
    return kind if kind in FAILURE_KINDS else "unknown"


def _clamp_percent(value: float) -> float:
    return round(max(0.0, min(100.0, float(value or 0.0))), 2)


def calculate_node_load(live: dict[str, Any], server: Server) -> dict[str, Any]:
    """Calculate resource saturation from CPU, RAM and link capacity.

    CPU pressure uses both sampled utilisation and load-average divided by
    core count.  RAM is relative to installed memory.  Network pressure is
    relative to the configured port width, or the latest measured download /
    upload capacity when width is set to auto.
    """
    cpu_count = max(1, int(live.get("cpu_count", 1) or 1))
    cpu_sample = float(live.get("cpu_percent", 0.0) or 0.0)
    load_pressure = float(live.get("load_1", 0.0) or 0.0) * 100.0 / cpu_count
    cpu_percent = _clamp_percent(max(cpu_sample, load_pressure))

    mem_total = max(0, int(live.get("mem_total", 0) or 0))
    mem_used = max(0, int(live.get("mem_used", 0) or 0))
    memory_percent = _clamp_percent(
        (mem_used * 100.0 / mem_total) if mem_total else 0.0
    )

    configured = max(0.0, float(getattr(server, "bandwidth_mbps", 0.0) or 0.0))
    measured_down = max(
        0.0, float(getattr(server, "speed_download_mbps", 0.0) or 0.0)
    )
    measured_up = max(
        0.0, float(getattr(server, "speed_upload_mbps", 0.0) or 0.0)
    )
    if configured > 0:
        down_capacity = up_capacity = configured
        capacity_source = "configured"
    else:
        down_capacity = measured_down or 100.0
        up_capacity = measured_up or down_capacity
        capacity_source = "speedtest" if measured_down or measured_up else "estimate"

    rx_mbps = max(0, int(live.get("net_rx_bps", 0) or 0)) * 8.0 / 1_000_000
    tx_mbps = max(0, int(live.get("net_tx_bps", 0) or 0)) * 8.0 / 1_000_000
    network_percent = _clamp_percent(
        max(
            rx_mbps * 100.0 / max(0.001, down_capacity),
            tx_mbps * 100.0 / max(0.001, up_capacity),
        )
    )

    overall = _clamp_percent(
        cpu_percent * 0.45 + memory_percent * 0.25 + network_percent * 0.30
    )
    return {
        "load_percent": overall,
        "cpu_load_percent": cpu_percent,
        "memory_percent": memory_percent,
        "network_percent": network_percent,
        "bandwidth_down_mbps": round(down_capacity, 2),
        "bandwidth_up_mbps": round(up_capacity, 2),
        "bandwidth_source": capacity_source,
    }


def enrich_live_payload(server: Server, payload: dict[str, Any]) -> dict[str, Any]:
    out = dict(payload)
    out.update(calculate_node_load(out, server))
    out.update(
        {
            "speed_download_mbps": float(server.speed_download_mbps or 0.0),
            "speed_upload_mbps": float(server.speed_upload_mbps or 0.0),
            "speed_latency_ms": float(server.speed_latency_ms or 0.0),
            "speed_tested_at": (
                server.speed_tested_at.isoformat() if server.speed_tested_at else None
            ),
            "speed_test_error": server.speed_test_error or "",
        }
    )
    return out


def _client_filters(server_id: int) -> list[Any]:
    return [
        Client.server_id == server_id,
        ~Client.label.in_([BALANCER_CLIENT_LABEL, BYPASS_CLIENT_LABEL]),
        ~Client.email.like("__balancer__-%"),
        ~Client.email.like("__bypass__-%"),
    ]


def _daily_row(db: Session, server_id: int, day: date) -> ServerMetricDaily:
    row = db.scalar(
        select(ServerMetricDaily).where(
            ServerMetricDaily.server_id == server_id,
            ServerMetricDaily.day == day,
        )
    )
    if row is None:
        row = ServerMetricDaily(server_id=server_id, day=day)
        db.add(row)
        db.flush()
    return row


def record_daily_traffic(
    db: Session, server_id: int, up_delta: int, down_delta: int
) -> None:
    """Fold exact xray counter deltas into the permanent daily roll-up."""
    up_delta = max(0, int(up_delta or 0))
    down_delta = max(0, int(down_delta or 0))
    if not up_delta and not down_delta:
        return
    row = _daily_row(db, server_id, datetime.utcnow().date())
    row.traffic_up_bytes += up_delta
    row.traffic_down_bytes += down_delta


def _collect_one_server(server_id: int) -> None:
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            return
        agent = AgentClient(server.agent_url, server.agent_token, timeout=AGENT_TIMEOUT_S)
        live: dict[str, Any] = {}
        online = False
        failure_kind = ""
        failure_detail = ""
        try:
            live = agent.live(online_window=120)
            online = True
            # Compatibility with agents released before expanded /live.
            if "mem_total" not in live:
                live.update(agent.sysinfo())
        except Exception as exc:  # noqa: BLE001
            # A dead agent does not by itself mean the whole node is down:
            # check the public VPN endpoint from the panel as a second signal.
            public_ok, public_detail = _tcp_reachable(server.public_host, int(server.port or 443))
            agent_ok, agent_detail = _tcp_reachable(server.agent_url, 8765)
            if public_ok:
                failure_kind = "network"
                failure_detail = (
                    f"agent unavailable: {type(exc).__name__}: {exc}; "
                    "public endpoint reachable"
                )
            elif agent_ok:
                failure_kind = "agent"
                failure_detail = f"agent HTTP check failed: {type(exc).__name__}: {exc}"
            else:
                failure_kind = "node"
                failure_detail = (
                    f"agent: {agent_detail or type(exc).__name__ + ': ' + str(exc)}; "
                    f"public: {public_detail or 'unreachable'}"
                )
            log.debug(
                "metrics: server=%s unavailable kind=%s: %s",
                server.name, failure_kind, failure_detail,
            )

        if online:
            # /live proves the agent is reachable; /health tells us whether
            # the protocol service that this node actually serves is active.
            try:
                health = agent.health()
                service = _service_name(server)
                service_key = "hysteria_active" if service == "hysteria" else "xray_active"
                if service_key in health and not bool(health.get(service_key)):
                    online = False
                    failure_kind = "xray"
                    failure_detail = f"{service} service is inactive"
            except Exception as exc:  # noqa: BLE001
                # Keep the live sample useful, but make this uncertainty
                # visible instead of silently reporting a healthy service.
                online = False
                failure_kind = "unknown"
                failure_detail = f"health check failed: {type(exc).__name__}: {exc}"

        if online:
            failure_kind = ""
            failure_detail = ""
        else:
            failure_kind = _failure_bucket(failure_kind)

        counts = db.execute(
            select(
                func.count(Client.id),
                func.coalesce(func.sum(Client.total_up), 0),
                func.coalesce(func.sum(Client.total_down), 0),
            ).where(*_client_filters(server.id))
        ).one()
        client_count, total_up, total_down = map(int, counts)
        load = calculate_node_load(live, server)
        now = datetime.utcnow()
        sample = ServerMetricSample(
            server_id=server.id,
            recorded_at=now,
            online=online,
            failure_kind=failure_kind,
            failure_detail=failure_detail[:2000],
            cpu_percent=float(load["cpu_load_percent"]),
            memory_percent=float(load["memory_percent"]),
            network_percent=float(load["network_percent"]),
            load_percent=float(load["load_percent"]),
            net_rx_bps=max(0, int(live.get("net_rx_bps", 0) or 0)),
            net_tx_bps=max(0, int(live.get("net_tx_bps", 0) or 0)),
            online_clients=max(0, int(live.get("online_clients", 0) or 0)),
            client_count=client_count,
            traffic_up_total=total_up,
            traffic_down_total=total_down,
        )
        db.add(sample)

        daily = _daily_row(db, server.id, now.date())
        daily.sample_count += 1
        if online:
            daily.online_sample_count += 1
        elif failure_kind == "xray":
            daily.xray_failure_count += 1
        elif failure_kind == "network":
            daily.network_failure_count += 1
        elif failure_kind == "node":
            daily.node_failure_count += 1
        elif failure_kind == "agent":
            daily.agent_failure_count += 1
        else:
            daily.unknown_failure_count += 1
        daily.cpu_sum += sample.cpu_percent
        daily.cpu_max = max(daily.cpu_max, sample.cpu_percent)
        daily.memory_sum += sample.memory_percent
        daily.memory_max = max(daily.memory_max, sample.memory_percent)
        daily.network_sum += sample.network_percent
        daily.network_max = max(daily.network_max, sample.network_percent)
        daily.load_sum += sample.load_percent
        daily.load_max = max(daily.load_max, sample.load_percent)
        daily.online_clients_sum += sample.online_clients
        daily.online_clients_max = max(daily.online_clients_max, sample.online_clients)
        daily.net_rx_bytes += sample.net_rx_bps * METRICS_INTERVAL_S
        daily.net_tx_bytes += sample.net_tx_bps * METRICS_INTERVAL_S
        db.commit()


def run_speedtest_for_server(server_id: int) -> dict[str, Any]:
    """Run and persist one speed test; callable by scheduler and API."""
    with SessionLocal() as db:
        server = db.get(Server, server_id)
        if server is None:
            raise ValueError("server not found")
        now = datetime.utcnow()
        result: dict[str, Any] = {}
        error = ""
        try:
            result = AgentClient(
                server.agent_url, server.agent_token, timeout=90
            ).speedtest()
        except Exception as exc:  # noqa: BLE001
            error = str(exc)[:1000]

        download = max(0.0, float(result.get("download_mbps", 0.0) or 0.0))
        upload = max(0.0, float(result.get("upload_mbps", 0.0) or 0.0))
        latency = max(0.0, float(result.get("latency_ms", 0.0) or 0.0))
        provider = str(result.get("provider", "") or "")[:64]
        server.speed_download_mbps = download
        server.speed_upload_mbps = upload
        server.speed_latency_ms = latency
        server.speed_tested_at = now
        server.speed_test_error = error
        db.add(
            ServerSpeedTest(
                server_id=server.id,
                tested_at=now,
                download_mbps=download,
                upload_mbps=upload,
                latency_ms=latency,
                provider=provider,
                error=error,
            )
        )
        db.commit()
        if error:
            log.info("speedtest: server=%s failed: %s", server.name, error)
        else:
            log.info(
                "speedtest: server=%s down=%.1f up=%.1f latency=%.1fms",
                server.name, download, upload, latency,
            )
        return {
            "server_id": server.id,
            "download_mbps": download,
            "upload_mbps": upload,
            "latency_ms": latency,
            "tested_at": now.isoformat(),
            "provider": provider,
            "error": error,
        }


def _statistics_client_totals(db: Session, server_ids: list[int]) -> tuple[int, int, int]:
    if not server_ids:
        return 0, 0, 0
    row = db.execute(
        select(
            func.count(Client.id),
            func.coalesce(func.sum(Client.total_up), 0),
            func.coalesce(func.sum(Client.total_down), 0),
        ).where(
            Client.server_id.in_(server_ids),
            ~Client.label.in_([BALANCER_CLIENT_LABEL, BYPASS_CLIENT_LABEL]),
            ~Client.email.like("__balancer__-%"),
            ~Client.email.like("__bypass__-%"),
        )
    ).one()
    return int(row[0]), int(row[1]), int(row[2])


def _uptime_state(row: ServerMetricSample) -> str:
    if bool(row.online):
        return "online"
    return _failure_bucket(getattr(row, "failure_kind", "") or "unknown")


def _uptime_from_raw(rows: list[ServerMetricSample]) -> dict[str, Any]:
    """Build exact day bars and contiguous failure intervals from samples."""
    by_day: dict[date, dict[str, Any]] = {}
    overall_counts = {kind: 0 for kind in (*FAILURE_KINDS, "online")}
    for row in rows:
        day = row.recorded_at.date()
        day_data = by_day.setdefault(
            day,
            {"sample_count": 0, "online_samples": 0, "failure_counts": {kind: 0 for kind in FAILURE_KINDS}, "segments": []},
        )
        state = _uptime_state(row)
        day_data["sample_count"] += 1
        overall_counts[state] = overall_counts.get(state, 0) + 1
        if state == "online":
            day_data["online_samples"] += 1
        else:
            day_data["failure_counts"][state] += 1

        start = row.recorded_at
        end = start + timedelta(seconds=METRICS_INTERVAL_S)
        segments = day_data["segments"]
        if segments and segments[-1]["kind"] == state:
            previous = segments[-1]
            previous_end = datetime.fromisoformat(previous["end"])
            if start <= previous_end + timedelta(seconds=METRICS_INTERVAL_S * 1.5):
                previous["end"] = max(previous_end, end).isoformat()
                previous["seconds"] = max(0.0, (max(previous_end, end) - datetime.fromisoformat(previous["start"])).total_seconds())
                continue
        segments.append({
            "kind": state,
            "start": start.isoformat(),
            "end": end.isoformat(),
            "seconds": float(METRICS_INTERVAL_S),
        })

    days: list[dict[str, Any]] = []
    for day, data in sorted(by_day.items()):
        count = int(data["sample_count"])
        online_samples = int(data["online_samples"])
        days.append({
            "date": day.isoformat(),
            "sample_count": count,
            "online_samples": online_samples,
            "uptime_percent": round(online_samples * 100.0 / count, 2) if count else None,
            "failure_counts": data["failure_counts"],
            "segments": data["segments"],
            "approximate": False,
        })
    total = sum(overall_counts.values())
    online = overall_counts.get("online", 0)
    unknown = overall_counts.get("unknown", 0)
    known = max(0, total - unknown)
    return {
        "sample_count": total,
        "online_samples": online,
        "known_samples": known,
        "unknown_samples": unknown,
        "coverage_percent": round(known * 100.0 / total, 2) if total else None,
        "uptime_percent": round(online * 100.0 / known, 2) if known else None,
        "failure_counts": {kind: overall_counts.get(kind, 0) for kind in FAILURE_KINDS},
        "days": days,
        "exact": True,
    }


def _uptime_from_daily(rows: list[ServerMetricDaily]) -> dict[str, Any]:
    """Build long-range uptime from permanent daily counters.

    Cause intervals cannot be reconstructed after raw samples expire, so the
    day bar is explicitly marked approximate and only conveys proportions.
    """
    total = online = known = 0
    failure_counts = {kind: 0 for kind in FAILURE_KINDS}
    days: list[dict[str, Any]] = []
    for row in rows:
        count = max(0, int(row.sample_count or 0))
        day_online = max(0, int(getattr(row, "online_sample_count", 0) or 0))
        day_failures = {
            "xray": max(0, int(getattr(row, "xray_failure_count", 0) or 0)),
            "network": max(0, int(getattr(row, "network_failure_count", 0) or 0)),
            "node": max(0, int(getattr(row, "node_failure_count", 0) or 0)),
            "agent": max(0, int(getattr(row, "agent_failure_count", 0) or 0)),
            "unknown": max(0, int(getattr(row, "unknown_failure_count", 0) or 0)),
        }
        known_day = day_online + sum(day_failures.values())
        unknown_day = max(0, count - known_day)
        if unknown_day:
            day_failures["unknown"] += unknown_day
        day_uptime = round(day_online * 100.0 / known_day, 2) if known_day else None
        segments = []
        for kind, units in [("online", day_online), *day_failures.items()]:
            if units:
                segments.append({"kind": kind, "units": units})
        online += day_online
        total += count
        known += known_day
        for kind, units in day_failures.items():
            failure_counts[kind] += units
        days.append({
            "date": row.day.isoformat(),
            "sample_count": count,
            "online_samples": day_online,
            "uptime_percent": day_uptime,
            "failure_counts": day_failures,
            "segments": segments,
            "approximate": True,
        })
    return {
        "sample_count": total,
        "online_samples": online,
        "known_samples": known,
        "unknown_samples": max(0, total - known),
        "coverage_percent": round(known * 100.0 / total, 2) if total else None,
        "uptime_percent": round(online * 100.0 / known, 2) if known else None,
        "failure_counts": failure_counts,
        "days": days,
        "exact": False,
    }


def _uptime_payload(
    db: Session, servers: list[Server], *, period: str, period_days: int
) -> dict[str, Any]:
    """Return per-node uptime cards plus a weighted fleet total."""
    server_ids = [server.id for server in servers]
    cutoff = datetime.utcnow() - timedelta(days=period_days)
    node_payload: list[dict[str, Any]] = []
    total_samples = total_online = total_known = 0
    total_unknown = 0
    fleet_failures = {kind: 0 for kind in FAILURE_KINDS}
    for server in servers:
        # Raw intervals are useful for the short-range outage timeline. For
        # 30d and longer, daily roll-ups keep the API responsive even on a
        # fleet with millions of samples; the UI marks those bars approximate.
        if period_days <= 7:
            rows = list(db.scalars(
                select(ServerMetricSample)
                .where(
                    ServerMetricSample.server_id == server.id,
                    ServerMetricSample.recorded_at >= cutoff,
                )
                .order_by(ServerMetricSample.recorded_at)
            ).all())
            card = _uptime_from_raw(rows)
        else:
            rows = list(db.scalars(
                select(ServerMetricDaily)
                .where(
                    ServerMetricDaily.server_id == server.id,
                    ServerMetricDaily.day >= cutoff.date(),
                )
                .order_by(ServerMetricDaily.day)
            ).all())
            card = _uptime_from_daily(rows)
        card.update({"server_id": server.id, "name": server.display_name or server.name})
        node_payload.append(card)
        total_samples += int(card.get("sample_count") or 0)
        total_online += int(card.get("online_samples") or 0)
        total_known += int(card.get("known_samples") or 0)
        total_unknown += int(card.get("unknown_samples") or 0)
        for kind, value in (card.get("failure_counts") or {}).items():
            fleet_failures[kind] += int(value or 0)
    return {
        "period": period,
        "days": period_days,
        "available_days": len({day.get("date") for card in node_payload for day in card.get("days", [])}),
        "period_coverage_percent": round(min(100.0, len({day.get("date") for card in node_payload for day in card.get("days", [])}) * 100.0 / max(1, period_days)), 2),
        "sample_count": total_samples,
        "online_samples": total_online,
        "known_samples": total_known,
        "unknown_samples": total_unknown,
        "coverage_percent": round(total_known * 100.0 / total_samples, 2) if total_samples else None,
        "uptime_percent": round(total_online * 100.0 / total_known, 2) if total_known else None,
        "failure_counts": fleet_failures,
        "nodes": node_payload,
        "exact": all(bool(card.get("exact")) for card in node_payload) if node_payload else True,
    }


def statistics_payload(
    db: Session, *, period: str = "30d", server_id: int = 0
) -> dict[str, Any]:
    period_days = {"24h": 1, "7d": 7, "30d": 30, "90d": 90, "365d": 365}
    if period not in period_days:
        raise ValueError("period must be one of 24h, 7d, 30d, 90d, 365d")
    stmt = select(Server).order_by(Server.id)
    if server_id:
        stmt = stmt.where(Server.id == server_id)
    servers = list(db.scalars(stmt).all())
    if server_id and not servers:
        raise LookupError("server not found")
    server_ids = [server.id for server in servers]
    client_count, total_up, total_down = _statistics_client_totals(db, server_ids)
    uptime = _uptime_payload(db, servers, period=period, period_days=period_days[period])
    uptime_by_server = {int(row["server_id"]): row for row in uptime["nodes"]}

    latest: dict[int, ServerMetricSample] = {}
    for sid in server_ids:
        sample = db.scalar(
            select(ServerMetricSample)
            .where(ServerMetricSample.server_id == sid)
            .order_by(ServerMetricSample.recorded_at.desc())
            .limit(1)
        )
        if sample is not None:
            latest[sid] = sample

    cutoff_live = datetime.utcnow() - timedelta(minutes=5)
    current_nodes: list[dict[str, Any]] = []
    for server in servers:
        sample = latest.get(server.id)
        current_nodes.append(
            {
                "id": server.id,
                "name": server.name,
                "display_name": server.display_name or server.name,
                "online": bool(sample and sample.online and sample.recorded_at >= cutoff_live),
                "load_percent": float(sample.load_percent if sample else 0.0),
                "cpu_percent": float(sample.cpu_percent if sample else 0.0),
                "memory_percent": float(sample.memory_percent if sample else 0.0),
                "network_percent": float(sample.network_percent if sample else 0.0),
                "online_clients": int(sample.online_clients if sample else 0),
                "net_rx_bps": int(sample.net_rx_bps if sample else 0),
                "net_tx_bps": int(sample.net_tx_bps if sample else 0),
                "speed_download_mbps": float(server.speed_download_mbps or 0.0),
                "speed_upload_mbps": float(server.speed_upload_mbps or 0.0),
                "speed_latency_ms": float(server.speed_latency_ms or 0.0),
                "speed_tested_at": (
                    server.speed_tested_at.isoformat() if server.speed_tested_at else None
                ),
                "speed_test_error": server.speed_test_error or "",
                "uptime": uptime_by_server.get(server.id, {
                    "uptime_percent": None,
                    "sample_count": 0,
                    "online_samples": 0,
                    "failure_counts": {kind: 0 for kind in FAILURE_KINDS},
                    "days": [],
                    "exact": True,
                }),
            }
        )

    series: list[dict[str, Any]] = []
    if period == "24h":
        since = datetime.utcnow() - timedelta(hours=24)
        rows = db.scalars(
            select(ServerMetricSample)
            .where(
                ServerMetricSample.server_id.in_(server_ids),
                ServerMetricSample.recorded_at >= since,
            )
            .order_by(ServerMetricSample.recorded_at)
        ).all()
        buckets: dict[datetime, dict[int, list[ServerMetricSample]]] = defaultdict(
            lambda: defaultdict(list)
        )
        for row in rows:
            bucket = row.recorded_at.replace(
                minute=(row.recorded_at.minute // 30) * 30,
                second=0,
                microsecond=0,
            )
            buckets[bucket][row.server_id].append(row)
        for bucket, by_server in sorted(buckets.items()):
            nodes = []
            for node_rows in by_server.values():
                n = len(node_rows)
                nodes.append(
                    {
                        "load": sum(r.load_percent for r in node_rows) / n,
                        "cpu": sum(r.cpu_percent for r in node_rows) / n,
                        "memory": sum(r.memory_percent for r in node_rows) / n,
                        "network": sum(r.network_percent for r in node_rows) / n,
                        "online": sum(r.online_clients for r in node_rows) / n,
                        "rx": sum(r.net_rx_bps for r in node_rows) / n,
                        "tx": sum(r.net_tx_bps for r in node_rows) / n,
                    }
                )
            count = max(1, len(nodes))
            series.append(
                {
                    "ts": bucket.isoformat(),
                    "load_percent": round(sum(n["load"] for n in nodes) / count, 2),
                    "cpu_percent": round(sum(n["cpu"] for n in nodes) / count, 2),
                    "memory_percent": round(sum(n["memory"] for n in nodes) / count, 2),
                    "network_percent": round(sum(n["network"] for n in nodes) / count, 2),
                    "online_clients": round(sum(n["online"] for n in nodes)),
                    "net_rx_bps": round(sum(n["rx"] for n in nodes)),
                    "net_tx_bps": round(sum(n["tx"] for n in nodes)),
                    "traffic_up_bytes": 0,
                    "traffic_down_bytes": 0,
                }
            )
    else:
        since_day = datetime.utcnow().date() - timedelta(days=period_days[period] - 1)
        rows = db.scalars(
            select(ServerMetricDaily)
            .where(
                ServerMetricDaily.server_id.in_(server_ids),
                ServerMetricDaily.day >= since_day,
            )
            .order_by(ServerMetricDaily.day)
        ).all()
        by_day: dict[date, list[ServerMetricDaily]] = defaultdict(list)
        for row in rows:
            by_day[row.day].append(row)
        for day, day_rows in sorted(by_day.items()):
            valid = [row for row in day_rows if row.sample_count > 0]
            count = max(1, len(valid))
            series.append(
                {
                    "ts": day.isoformat(),
                    "load_percent": round(sum(r.load_sum / r.sample_count for r in valid) / count, 2),
                    "load_max": round(max((r.load_max for r in day_rows), default=0.0), 2),
                    "cpu_percent": round(sum(r.cpu_sum / r.sample_count for r in valid) / count, 2),
                    "memory_percent": round(sum(r.memory_sum / r.sample_count for r in valid) / count, 2),
                    "network_percent": round(sum(r.network_sum / r.sample_count for r in valid) / count, 2),
                    "online_clients": round(sum(r.online_clients_sum / r.sample_count for r in valid)),
                    "net_rx_bytes": sum(r.net_rx_bytes for r in day_rows),
                    "net_tx_bytes": sum(r.net_tx_bytes for r in day_rows),
                    "traffic_up_bytes": sum(r.traffic_up_bytes for r in day_rows),
                    "traffic_down_bytes": sum(r.traffic_down_bytes for r in day_rows),
                }
            )

    tested_since = datetime.utcnow() - timedelta(days=period_days[period])
    speed_rows = db.scalars(
        select(ServerSpeedTest)
        .where(
            ServerSpeedTest.server_id.in_(server_ids),
            ServerSpeedTest.tested_at >= tested_since,
        )
        .order_by(ServerSpeedTest.tested_at)
    ).all()
    speedtests = [
        {
            "server_id": row.server_id,
            "tested_at": row.tested_at.isoformat(),
            "download_mbps": row.download_mbps,
            "upload_mbps": row.upload_mbps,
            "latency_ms": row.latency_ms,
            "error": row.error,
        }
        for row in speed_rows
    ]
    active_samples = [latest[sid] for sid in server_ids if sid in latest]
    speed_nodes = [s for s in servers if s.speed_download_mbps or s.speed_upload_mbps]
    return {
        "period": period,
        "server_id": server_id or None,
        "summary": {
            "servers": len(servers),
            "online_servers": sum(1 for row in current_nodes if row["online"]),
            "clients": client_count,
            "online_clients": sum(row["online_clients"] for row in current_nodes),
            "load_percent": round(
                sum(s.load_percent for s in active_samples) / max(1, len(active_samples)), 2
            ),
            "net_rx_bps": sum(s.net_rx_bps for s in active_samples),
            "net_tx_bps": sum(s.net_tx_bps for s in active_samples),
            "traffic_up_total": total_up,
            "traffic_down_total": total_down,
            "speed_download_mbps": round(
                sum(s.speed_download_mbps for s in speed_nodes) / max(1, len(speed_nodes)), 2
            ),
            "speed_upload_mbps": round(
                sum(s.speed_upload_mbps for s in speed_nodes) / max(1, len(speed_nodes)), 2
            ),
            "uptime_percent": uptime["uptime_percent"],
            "uptime_samples": uptime["sample_count"],
            "uptime_online_samples": uptime["online_samples"],
            "uptime_known_samples": uptime["known_samples"],
            "uptime_unknown_samples": uptime["unknown_samples"],
            "uptime_coverage_percent": uptime["coverage_percent"],
            "uptime_available_days": uptime["available_days"],
            "uptime_period_coverage_percent": uptime["period_coverage_percent"],
            "uptime_failures": uptime["failure_counts"],
        },
        "nodes": current_nodes,
        "uptime": uptime,
        "series": series,
        "speedtests": speedtests,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _list_server_ids() -> list[int]:
    with SessionLocal() as db:
        return [int(value) for value in db.scalars(select(Server.id)).all()]


def _due_speedtest_ids() -> list[int]:
    cutoff = datetime.utcnow() - timedelta(seconds=SPEEDTEST_INTERVAL_S)
    with SessionLocal() as db:
        return [
            int(value)
            for value in db.scalars(
                select(Server.id)
                .where(
                    (Server.speed_tested_at.is_(None))
                    | (Server.speed_tested_at <= cutoff)
                )
                .order_by(Server.id)
            ).all()
        ]


def _prune_raw_samples() -> None:
    cutoff = datetime.utcnow() - timedelta(days=RAW_RETENTION_DAYS)
    with SessionLocal() as db:
        db.execute(
            delete(ServerMetricSample).where(ServerMetricSample.recorded_at < cutoff)
        )
        db.commit()


class MetricsSyncManager:
    def __init__(self) -> None:
        self._metrics_task: Optional[asyncio.Task] = None
        self._speed_task: Optional[asyncio.Task] = None
        self._stopping = asyncio.Event()

    async def start(self) -> None:
        if self._metrics_task and not self._metrics_task.done():
            return
        self._stopping.clear()
        self._metrics_task = asyncio.create_task(
            self._metrics_loop(), name="metrics-sync"
        )
        self._speed_task = asyncio.create_task(
            self._speedtest_loop(), name="speedtest-sync"
        )
        log.info(
            "metrics sync started: samples=%ss speedtest=%ss",
            METRICS_INTERVAL_S, SPEEDTEST_INTERVAL_S,
        )

    async def stop(self) -> None:
        self._stopping.set()
        tasks = [task for task in (self._metrics_task, self._speed_task) if task]
        for task in tasks:
            if not task.done():
                task.cancel()
        for task in tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._metrics_task = self._speed_task = None

    async def _metrics_loop(self) -> None:
        await asyncio.sleep(3)
        sweeps = 0
        while not self._stopping.is_set():
            try:
                ids = await asyncio.to_thread(_list_server_ids)
                semaphore = asyncio.Semaphore(8)

                async def collect(server_id: int) -> None:
                    async with semaphore:
                        await asyncio.to_thread(_collect_one_server, server_id)

                await asyncio.gather(*(collect(sid) for sid in ids))
                sweeps += 1
                if sweeps == 1 or sweeps % max(1, 86400 // METRICS_INTERVAL_S) == 0:
                    await asyncio.to_thread(_prune_raw_samples)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("metrics sweep failed")
            try:
                await asyncio.wait_for(
                    self._stopping.wait(), timeout=METRICS_INTERVAL_S
                )
            except asyncio.TimeoutError:
                pass

    async def _speedtest_loop(self) -> None:
        await asyncio.sleep(10)
        while not self._stopping.is_set():
            try:
                due = await asyncio.to_thread(_due_speedtest_ids)
                # Tests are staggered to avoid every node saturating its link at
                # the same instant after a panel restart.
                for index, server_id in enumerate(due):
                    if index:
                        await asyncio.sleep(5)
                    await asyncio.to_thread(run_speedtest_for_server, server_id)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                log.exception("scheduled speed test failed")
            try:
                await asyncio.wait_for(self._stopping.wait(), timeout=60)
            except asyncio.TimeoutError:
                pass


manager = MetricsSyncManager()

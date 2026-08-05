from __future__ import annotations

from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

from panel import app as panel_app
from panel.metrics_sync import _uptime_from_raw


class _FakeDb:
    def __init__(self, server):
        self.server = server

    def get(self, _model, server_id):
        return self.server if server_id == self.server.id else None


def test_security_timeout_is_an_available_false_payload() -> None:
    server = SimpleNamespace(
        id=7, name="offline-node", agent_url="https://node", agent_token="secret"
    )
    with patch.object(
        panel_app.AgentClient,
        "security_sessions",
        side_effect=TimeoutError("node timeout"),
    ):
        payload = panel_app.api_server_security_sessions(
            7, window_seconds=600, min_events=1, _=object(), db=_FakeDb(server)
        )

    assert payload["available"] is False
    assert payload["clients"] == []
    assert payload["server_id"] == 7
    assert "TimeoutError" in payload["error"]


def test_raw_uptime_contains_response_times_and_failure_intervals() -> None:
    started = datetime(2026, 8, 6, 10, 0, 0)
    rows = [
        SimpleNamespace(
            recorded_at=started,
            online=True,
            failure_kind="",
            failure_detail="",
            response_ms=42.5,
        ),
        SimpleNamespace(
            recorded_at=started + timedelta(seconds=60),
            online=False,
            failure_kind="xray",
            failure_detail="xray inactive",
            response_ms=91.0,
        ),
        SimpleNamespace(
            recorded_at=started + timedelta(seconds=120),
            online=False,
            failure_kind="network",
            failure_detail="connect timeout",
            response_ms=5000.0,
        ),
    ]

    card = _uptime_from_raw(rows)

    assert card["sample_count"] == 3
    assert card["uptime_percent"] == 33.33
    assert card["response_ms_min"] == 42.5
    assert card["response_ms_max"] == 5000.0
    assert card["failure_counts"]["xray"] == 1
    assert card["failure_counts"]["network"] == 1
    assert [point["kind"] for point in card["response_series"]] == [
        "online",
        "xray",
        "network",
    ]
    assert card["days"][0]["segments"][1]["detail"] == "xray inactive"

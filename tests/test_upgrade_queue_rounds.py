from __future__ import annotations

from collections import Counter
from unittest.mock import patch

from panel import app as panel_app


def _job() -> dict:
    return {
        "id": "round-job",
        "created_at": 1.0,
        "started_at": None,
        "finished_at": None,
        "total": 2,
        "done": False,
        "cancel_requested": False,
        "current_index": None,
        "current_server_id": None,
        "retry_round": 1,
        "nodes": [
            {"server_id": 1, "name": "online", "status": "pending", "attempt": 0},
            {"server_id": 2, "name": "offline", "status": "pending", "attempt": 0},
        ],
    }


def test_failed_node_moves_to_next_round_without_repeating_success() -> None:
    calls: Counter[int] = Counter()
    plan = [
        {"server_id": 1, "name": "online", "agent_url": "a", "agent_token": "t"},
        {"server_id": 2, "name": "offline", "agent_url": "b", "agent_token": "t"},
    ]
    panel_app._upgrade_jobs["round-job"] = _job()
    panel_app._upgrade_worker_ids.add("round-job")

    def run(job_id, server_id, *_args):
        calls[server_id] += 1
        if server_id == 2 and calls[server_id] == 1:
            panel_app._set_upgrade_node_status(
                job_id, server_id, status="timeout", ok=False
            )
            return {"ok": False, "status": "timeout"}
        panel_app._set_upgrade_node_status(job_id, server_id, status="ok", ok=True)
        return {"ok": True, "status": "ok"}

    try:
        with (
            patch.object(panel_app, "_run_upgrade_node", side_effect=run),
            patch.object(panel_app, "_upgrade_wait_or_cancel", return_value=False),
            patch.object(panel_app, "_persist_upgrade_job_locked"),
        ):
            panel_app._upgrade_job_worker("round-job", plan)

        job = panel_app._upgrade_jobs["round-job"]
        assert calls == Counter({2: 2, 1: 1})
        assert job["retry_round"] == 2
        assert job["done"] is True
        assert all(node["status"] == "ok" for node in job["nodes"])
    finally:
        panel_app._upgrade_jobs.pop("round-job", None)
        panel_app._upgrade_worker_ids.discard("round-job")


def test_attempt_number_is_cumulative_across_rounds() -> None:
    job = _job()
    job["nodes"] = [
        {"server_id": 2, "name": "offline", "status": "pending", "attempt": 3}
    ]
    panel_app._upgrade_jobs["round-job"] = job

    class OfflineClient:
        def __init__(self, *_args, **_kwargs):
            pass

        def system_upgrade(self):
            raise RuntimeError("offline")

    try:
        with (
            patch.object(panel_app, "AgentClient", OfflineClient),
            patch.object(panel_app, "_probe_installed_sha", return_value=("", "")),
            patch.object(panel_app, "_upgrade_wait_or_cancel", return_value=False),
            patch.object(panel_app, "_persist_upgrade_job_locked"),
            patch.object(panel_app, "_UPGRADE_MAX_ATTEMPTS", 2),
        ):
            result = panel_app._run_upgrade_node(
                "round-job", 2, "offline", "https://offline", "token"
            )

        assert result["status"] == "timeout"
        assert panel_app._upgrade_jobs["round-job"]["nodes"][0]["attempt"] == 5
    finally:
        panel_app._upgrade_jobs.pop("round-job", None)

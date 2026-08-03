from __future__ import annotations

import unittest
from unittest.mock import patch

from agent import agent


class UpgradeCommandTests(unittest.TestCase):
    def test_exit_code_is_captured_before_journal_forwarding(self) -> None:
        with (
            patch.object(agent, "XNPANEL_BIN", "/usr/local/bin/xnpanel"),
            patch.object(
                agent,
                "XNPANEL_UPGRADE_STATUS",
                agent.Path("/var/lib/xnpanel/upgrade-status"),
            ),
        ):
            command = agent._upgrade_command(
                job_id="abc123",
                unit="xnpanel-upgrade-abc123.service",
                started_at="2026-08-03T17:00:00+00:00",
                status_path="/var/lib/xnpanel/upgrade-status",
            )

        self.assertIn('update --force >"$log_file" 2>&1', command)
        self.assertIn("rc=$?", command)
        self.assertIn('systemd-cat -t xnpanel-upgrade <"$log_file" || true', command)
        self.assertIn('EXIT_CODE=%s', command)
        self.assertNotIn("PIPESTATUS", command)


if __name__ == "__main__":
    unittest.main()

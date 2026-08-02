from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import agent


def _config(users: dict[str, str], *, listen: str = ":443") -> dict:
    return {
        "listen": listen,
        "auth": {"type": "userpass", "userpass": users},
        "acme": {"domains": ["example.com"], "email": "ops@example.com"},
    }


class HysteriaHotAuthTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.runtime = root / "config.yaml"
        self.desired = root / "config.yaml.panel"
        self.patches = [
            patch.object(agent, "HYSTERIA_CONFIG", self.runtime),
            patch.object(agent, "HYSTERIA_PANEL_CONFIG", self.desired),
            patch.object(agent, "HYSTERIA_BIN", "/bin/true"),
            patch.object(agent, "_ensure_hysteria_config_permissions"),
            patch.object(agent, "_systemctl_active", return_value=True),
        ]
        for item in self.patches:
            item.start()
        agent._set_hysteria_auth_config(None)

    def tearDown(self) -> None:
        for item in reversed(self.patches):
            item.stop()
        agent._set_hysteria_auth_config(None)
        self.tmp.cleanup()

    def test_auth_only_update_does_not_restart(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(agent, "_run", side_effect=fake_run):
            first = agent.put_hysteria_config(
                agent.ConfigIn(config=_config({"Alice": "one"}))
            )
            second = agent.put_hysteria_config(
                agent.ConfigIn(config=_config({"Alice": "two", "Bob": "three"}))
            )

        restarts = [cmd for cmd in calls if cmd[:2] == ["systemctl", "restart"]]
        enables = [cmd for cmd in calls if cmd[:2] == ["systemctl", "enable"]]
        self.assertTrue(first["restarted"])
        self.assertFalse(second["restarted"])
        self.assertEqual(second["method"], "http_auth")
        self.assertEqual(len(restarts), 1)
        self.assertEqual(len(enables), 2)
        self.assertEqual(
            agent._read_hysteria_yaml(self.runtime)["auth"]["type"], "http"
        )
        self.assertEqual(
            agent._read_hysteria_yaml(self.desired)["auth"]["userpass"]["Bob"],
            "three",
        )

    def test_structural_update_restarts(self) -> None:
        calls: list[list[str]] = []

        def fake_run(cmd: list[str], **_: object) -> subprocess.CompletedProcess[str]:
            calls.append(cmd)
            return subprocess.CompletedProcess(cmd, 0, "", "")

        with patch.object(agent, "_run", side_effect=fake_run):
            agent.put_hysteria_config(agent.ConfigIn(config=_config({"a": "1"})))
            result = agent.put_hysteria_config(
                agent.ConfigIn(config=_config({"a": "1"}, listen=":8443"))
            )

        restarts = [cmd for cmd in calls if cmd[:2] == ["systemctl", "restart"]]
        enables = [cmd for cmd in calls if cmd[:2] == ["systemctl", "enable"]]
        self.assertTrue(result["restarted"])
        self.assertEqual(len(restarts), 2)
        self.assertEqual(len(enables), 2)

    def test_userpass_auth_is_case_insensitive(self) -> None:
        agent._set_hysteria_auth_config(_config({"Alice": "secret"}))
        self.assertEqual(agent._hysteria_authenticate("ALICE:secret"), (True, "alice"))
        self.assertEqual(agent._hysteria_authenticate("alice:wrong"), (False, ""))


if __name__ == "__main__":
    unittest.main()

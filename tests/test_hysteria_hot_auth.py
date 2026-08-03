from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from agent import agent
from panel.models import Client, Server
from panel import xray_push


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
            # /bin/true exists on Linux production hosts. Keep this unit test
            # portable to Windows development runners as well.
            patch.object(agent.shutil, "which", return_value="/bin/true"),
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


class HysteriaPanelPushTests(unittest.TestCase):
    def test_new_panel_client_uses_hysteria_endpoint_with_full_auth_list(self) -> None:
        server = Server(
            id=17,
            name="hysteria-node",
            agent_url="http://node.internal:8765",
            agent_token="agent-token",
            protocol="hysteria2",
            mode="standalone",
            public_host="hy2.example.com",
            port=443,
            sni="hy2.example.com",
            dest="hy2.example.com:443",
            private_key="unused",
            public_key="unused",
            short_id="unused",
            hysteria_listen="",
            hysteria_auth_mode="userpass",
            hysteria_tls_mode="acme",
            hysteria_acme_email="ops@example.com",
            hysteria_stats_secret="stats-secret",
        )
        server.clients = [
            Client(
                id=91,
                server_id=17,
                uuid="new-client-password",
                email="subscription-client",
                label="subscription-client",
                flow="",
                total_up=0,
                total_down=0,
                enabled=True,
            )
        ]
        agent_client = MagicMock()

        with patch.object(xray_push, "AgentClient", return_value=agent_client):
            xray_push.push_config(server)

        agent_client.put_config.assert_not_called()
        agent_client.put_hysteria_config.assert_called_once()
        pushed = agent_client.put_hysteria_config.call_args.args[0]
        self.assertEqual(
            pushed["auth"]["userpass"]["subscription-client"],
            "new-client-password",
        )


if __name__ == "__main__":
    unittest.main()

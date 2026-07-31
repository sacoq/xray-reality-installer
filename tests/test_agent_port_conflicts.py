from __future__ import annotations

import unittest
import subprocess
from unittest.mock import patch

from fastapi import HTTPException

from agent import agent


class ManagedPortConflictTests(unittest.TestCase):
    def test_hysteria_config_is_readable_by_dedicated_service_user(self) -> None:
        path = agent.Path("/etc/hysteria/config.yaml")
        completed = subprocess.CompletedProcess(
            args=["chown"], returncode=0, stdout="", stderr=""
        )
        with (
            patch.object(agent, "_hysteria_service_identity", return_value=("hysteria", "hysteria")),
            patch.object(agent, "_run", return_value=completed) as run,
            patch.object(agent.os, "chmod") as chmod,
        ):
            agent._ensure_hysteria_config_permissions(path)
        run.assert_called_once_with(
            ["chown", "hysteria:hysteria", str(path)], check=False, timeout=5
        )
        chmod.assert_called_once_with(path, 0o640)

    def test_root_run_hysteria_keeps_private_config_mode(self) -> None:
        path = agent.Path("/etc/hysteria/config.yaml")
        with patch.object(agent, "_hysteria_service_identity", return_value=("root", "root")), patch.object(agent.os, "chmod") as chmod:
            agent._ensure_hysteria_config_permissions(path)
        chmod.assert_called_once_with(path, 0o600)

    def test_rejects_vpn_port_even_without_live_listener(self) -> None:
        with (
            patch.object(agent, "_xray_inbound_ports", return_value=set()),
            patch.object(agent, "_port_in_hysteria_listen", return_value=False),
            patch.object(agent, "_tcp_listeners", return_value=""),
        ):
            with self.assertRaises(HTTPException) as raised:
                agent._assert_managed_port_free(
                    443, purpose="SNI endpoint", vpn_port=443
                )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("VPN inbound", str(raised.exception.detail))

    def test_rejects_hysteria_port_for_sni_or_haproxy(self) -> None:
        with (
            patch.object(agent, "_xray_inbound_ports", return_value=set()),
            patch.object(agent, "_port_in_hysteria_listen", return_value=True),
            patch.object(agent, "_tcp_listeners", return_value=""),
        ):
            with self.assertRaises(HTTPException) as raised:
                agent._assert_managed_port_free(2443, purpose="HAProxy bridge")
        self.assertIn("Hysteria listen", str(raised.exception.detail))

    def test_rejects_existing_unmanaged_tcp_listener(self) -> None:
        listener = 'LISTEN 0 128 0.0.0.0:9443 0.0.0.0:* users:(("caddy",pid=1,fd=7))'
        with (
            patch.object(agent, "_xray_inbound_ports", return_value=set()),
            patch.object(agent, "_port_in_hysteria_listen", return_value=False),
            patch.object(agent, "_tcp_listeners", return_value=listener),
        ):
            with self.assertRaises(HTTPException) as raised:
                agent._assert_managed_port_free(9443, purpose="SNI endpoint")
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("already in use", str(raised.exception.detail))

    def test_allows_idempotent_managed_haproxy_listener(self) -> None:
        listener = 'LISTEN 0 128 0.0.0.0:2443 0.0.0.0:* users:(("haproxy",pid=2,fd=7))'
        with (
            patch.object(agent, "_xray_inbound_ports", return_value=set()),
            patch.object(agent, "_port_in_hysteria_listen", return_value=False),
            patch.object(agent, "_tcp_listeners", return_value=listener),
        ):
            agent._assert_managed_port_free(
                2443, purpose="HAProxy bridge", allow_haproxy=True
            )

    def test_rejects_xray_config_on_managed_sni_port(self) -> None:
        config = {"inbounds": [{"port": 9443}, {"port": 443}]}
        with patch.object(agent, "_managed_sni_ports", return_value={9443}):
            with self.assertRaises(HTTPException) as raised:
                agent._assert_vpn_config_avoids_managed_sni(
                    config, hysteria=False
                )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("9443", str(raised.exception.detail))

    def test_rejects_hysteria_range_covering_managed_sni_port(self) -> None:
        config = {"listen": ":9000-10000"}
        with patch.object(agent, "_managed_sni_ports", return_value={9443}):
            with self.assertRaises(HTTPException) as raised:
                agent._assert_vpn_config_avoids_managed_sni(
                    config, hysteria=True
                )
        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("9443", str(raised.exception.detail))

    def test_allows_vpn_config_on_distinct_port(self) -> None:
        with patch.object(agent, "_managed_sni_ports", return_value={9443}):
            agent._assert_vpn_config_avoids_managed_sni(
                {"inbounds": [{"port": 443}]}, hysteria=False
            )
            agent._assert_vpn_config_avoids_managed_sni(
                {"listen": ":20000-30000"}, hysteria=True
            )


if __name__ == "__main__":
    unittest.main()

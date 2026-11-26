from contextlib import ExitStack
import json
from pathlib import Path
from subprocess import CompletedProcess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from fastapi import HTTPException

from agent import agent


def reality(port, *, listen="0.0.0.0", proxy=False):
    return {
        "tag": "vless-reality",
        "listen": listen,
        "port": port,
        "protocol": "vless",
        "streamSettings": {
            "security": "reality",
            "sockopt": {"acceptProxyProtocol": proxy},
        },
    }


class RealityPortFirewallTests(unittest.TestCase):
    def setUp(self):
        self.stack = self.enterContext(ExitStack())
        root = Path(self.stack.enter_context(TemporaryDirectory()))
        self.path = root / "config.json"
        self.proxy_state = root / "proxy-firewall.json"
        self.current = {"inbounds": [reality(443)]}
        self.path.write_text(json.dumps(self.current))
        self.ufw_status = (
            "Status: active\n\n443/tcp ALLOW Anywhere\n"
            "443/tcp (v6) ALLOW Anywhere (v6)\n"
        )
        self.commands = []
        self.test_code = self.ufw_code = 0
        for name, replacement in {
            "XRAY_CONFIG": self.path,
            "PROXY_PROTOCOL_STATE": self.proxy_state,
        }.items():
            self.stack.enter_context(patch.object(agent, name, replacement))
        for name in (
            "_normalise_xray_access_log", "_assert_vpn_config_avoids_managed_sni",
            "_prepare_xray_access_log", "_restart_xray_managed", "_systemctl_active",
        ):
            self.stack.enter_context(patch.object(agent, name))
        self.restart = agent._restart_xray_managed
        self.stack.enter_context(patch.object(agent.shutil, "which", return_value="/usr/sbin/ufw"))
        self.stack.enter_context(patch.object(agent, "_run", side_effect=self.run_command))

    def run_command(self, command, **kwargs):
        self.commands.append(command)
        if command[-2:] == ["ufw", "status"]:
            return CompletedProcess(command, 0, self.ufw_status, "")
        if command[0] == "ufw":
            return CompletedProcess(command, self.ufw_code, "", "UFW failed")
        return CompletedProcess(command, self.test_code, "", "Xray rejected config")

    def apply(self, inbound):
        return agent.put_config(agent.ConfigIn(config={"inbounds": [inbound]}))

    def changes(self):
        return [command for command in self.commands if command[:2] == ["ufw", "allow"]]

    def test_moves_public_port_from_443_to_48443(self):
        result = self.apply(reality(48443))
        self.assertEqual(self.changes(), [["ufw", "allow", "48443/tcp"]])
        self.assertEqual(result.method, "restart")
        self.apply(reality(48443))
        self.assertEqual(len(self.changes()), 1)

    def test_keeps_an_ipv4_only_allowance_ipv4_only(self):
        self.ufw_status = "Status: active\n443/tcp ALLOW Anywhere\n"
        self.apply(reality(48443))
        self.assertEqual(self.changes(), [
            ["ufw", "allow", "from", "0.0.0.0/0", "to", "any", "port", "48443", "proto", "tcp"],
        ])

    def test_does_not_open_a_port_reserved_for_bridge_sources(self):
        self.proxy_state.write_text(json.dumps({"ports": {"48443": ["192.0.2.40"]}}))
        self.apply(reality(48443))
        self.assertFalse(self.changes())

    def test_validation_failure_keeps_firewall_and_config(self):
        self.test_code = 1
        with self.assertRaises(HTTPException):
            self.apply(reality(48443))
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(json.loads(self.path.read_text()), self.current)

    def test_same_port_and_nonpublic_listeners_skip_ufw(self):
        for inbound in (reality(443), reality(48443, listen="127.0.0.1"), reality(48443, proxy=True)):
            with self.subTest(inbound=inbound):
                self.path.write_text(json.dumps(self.current))
                self.commands.clear()
                self.apply(inbound)
                self.assertEqual(len(self.commands), 1)

    def test_keeps_restricted_rules_and_inactive_firewall(self):
        for status in (
            "Status: inactive\n",
            "Status: active\n443/tcp ALLOW 192.0.2.40\n",
            "Status: active\n443/tcp ALLOW Anywhere\n48443/tcp DENY Anywhere\n",
        ):
            with self.subTest(status=status):
                self.path.write_text(json.dumps(self.current))
                self.ufw_status = status
                self.apply(reality(48443))
                self.assertFalse(self.changes())

    def test_ufw_failure_keeps_old_config(self):
        self.ufw_code = 1
        with self.assertRaisesRegex(HTTPException, "48443"):
            self.apply(reality(48443))
        self.restart.assert_not_called()
        self.assertEqual(json.loads(self.path.read_text()), self.current)

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import agent


class LocalSniEndpointTests(unittest.TestCase):
    def test_provision_uses_only_loopback_and_removes_stock_default(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            conf_dir = root / "conf.d"
            conf_dir.mkdir()
            sites_available = root / "sites-available"
            sites_available.mkdir()
            stock = sites_available / "default"
            stock.write_text("server { listen 80 default_server; root /var/www/html; server_name _; }")
            enabled = root / "sites-enabled" / "default"
            enabled.parent.mkdir()
            enabled.symlink_to(stock)
            commands: list[list[str]] = []

            def fake_run(command, **kwargs):
                commands.append(command)
                if command[:2] == ["openssl", "req"]:
                    Path(command[command.index("-keyout") + 1]).write_text("key")
                    Path(command[command.index("-out") + 1]).write_text("cert")
                return subprocess.CompletedProcess(command, 0, "", "")

            body = agent.SniEndpointIn(
                domain="pops.xanka.best", email="ops@example.com",
                port=9443, vpn_port=9432,
            )
            with (
                patch.object(agent, "SNI_ENDPOINT_DIR", root / "certs"),
                patch.object(agent, "SNI_NGINX_CONF_DIR", conf_dir),
                patch.object(agent, "SNI_DEFAULT_SITE", enabled),
                patch.object(agent, "_assert_managed_port_free"),
                patch.object(agent, "_run", side_effect=fake_run),
                patch.object(agent.shutil, "which", return_value="/usr/bin/tool"),
            ):
                result = agent.provision_sni_endpoint(body)

            config = (conf_dir / "xnpanel-sni-pops.xanka.best.conf").read_text()
            self.assertIn("listen 127.0.0.1:9443 ssl", config)
            self.assertNotIn("listen 80", config)
            self.assertNotIn("listen 443", config)
            self.assertFalse(enabled.exists())
            self.assertEqual(result["dest"], "127.0.0.1:9443")
            self.assertFalse(any(command[0] == "certbot" for command in commands))


if __name__ == "__main__":
    unittest.main()

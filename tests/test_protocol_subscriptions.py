from __future__ import annotations

import json
import unittest

import yaml

from panel.app import (
    _client_connection_link,
    _render_clash,
    _render_singbox,
)
from panel.models import Client, Server


def _client(*, server_id: int = 1) -> Client:
    return Client(
        id=10,
        server_id=server_id,
        email="alice@example.com",
        uuid="client-secret",
        label="Alice",
        flow="",
        enabled=True,
    )


class ProtocolSubscriptionTests(unittest.TestCase):
    def test_hysteria_singbox_and_clash_entries(self) -> None:
        server = Server(
            id=1,
            name="hy2-fi",
            display_name="Finland",
            protocol="hysteria2",
            public_host="hy2.example.com",
            port=443,
            sni="tls.example.com",
            dest="",
            hysteria_listen="20000-50000",
            hysteria_obfs_type="salamander",
            hysteria_obfs_password="obfs-secret",
            pool_tier="",
            in_pool=False,
            mode="standalone",
        )
        client = _client()

        singbox = json.loads(_render_singbox([(client, server)], "test"))
        outbound = next(
            item for item in singbox["outbounds"] if item["type"] == "hysteria2"
        )
        self.assertEqual(outbound["server"], "hy2.example.com")
        self.assertEqual(outbound["server_ports"], ["20000:50000"])
        self.assertEqual(outbound["password"], "alice@example.com:client-secret")
        self.assertEqual(outbound["tls"]["server_name"], "tls.example.com")
        self.assertEqual(outbound["obfs"]["type"], "salamander")
        self.assertNotIn("up_mbps", outbound)

        clash = yaml.safe_load(_render_clash([(client, server)], "test"))
        proxy = clash["proxies"][0]
        self.assertEqual(proxy["type"], "hysteria2")
        self.assertEqual(proxy["ports"], "20000-50000")
        self.assertEqual(proxy["password"], "alice@example.com:client-secret")

    def test_vless_link_switches_to_bridge_endpoint_only(self) -> None:
        server = Server(
            id=2,
            name="eu-vless",
            protocol="vless-reality",
            public_host="eu.example.com",
            port=443,
            sni="www.example.com",
            dest="www.example.com:443",
            private_key="private",
            public_key="public",
            short_id="a1b2c3d4",
            transport="tcp",
            bridge_enabled=True,
            bridge_public_host="ru.example.com",
            bridge_port=2443,
            mode="standalone",
        )
        client = _client(server_id=2)
        client.flow = "xtls-rprx-vision"

        link = _client_connection_link(client, server)
        self.assertTrue(link.startswith("vless://"))
        self.assertIn("@ru.example.com:2443", link)
        self.assertIn("sni=www.example.com", link)
        self.assertIn("pbk=public", link)
        self.assertNotIn("@eu.example.com:443", link)


if __name__ == "__main__":
    unittest.main()

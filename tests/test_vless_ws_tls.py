from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, urlsplit

import yaml

from panel.app import _client_connection_link, _render_clash, _render_singbox
from panel.models import Client, Server
from panel.xray_config import build_vless_ws_tls_config


class VlessWsTlsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.server = Server(
            id=77,
            name="ws-node",
            protocol="vless-ws-tls",
            public_host="wow.breathtaking.uk",
            port=443,
            sni="",
            dest="",
            transport="ws",
            transport_path="/internal/events/channel/stream",
            ws_inbound_port=5443,
            mode="standalone",
        )
        self.client = Client(
            id=1,
            server_id=77,
            uuid="bf126e21-077d-46bb-ae1d-9944515a01e5",
            email="alice@example.com",
            label="WS test",
            enabled=True,
        )

    def test_loopback_config_has_no_tls_or_reality(self) -> None:
        config = build_vless_ws_tls_config(
            ws_port=5443,
            ws_path="/v1/stream/telemetry",
            clients=[{"id": self.client.uuid, "email": self.client.email}],
        )
        inbound = next(item for item in config["inbounds"] if item["tag"] == "WS")
        self.assertEqual(inbound["listen"], "127.0.0.1")
        self.assertEqual(inbound["port"], 5443)
        self.assertEqual(inbound["streamSettings"], {
            "network": "ws", "security": "none",
            "wsSettings": {"path": "/v1/stream/telemetry"},
        })
        self.assertNotIn("realitySettings", inbound["streamSettings"])
        self.assertEqual(config["outbounds"][0]["tag"], "DIRECT")
        self.assertEqual(config["outbounds"][1]["tag"], "BLOCK")

    def test_link_omits_sni_when_not_explicitly_set(self) -> None:
        link = _client_connection_link(self.client, self.server)
        query = parse_qs(urlsplit(link).query)
        self.assertEqual(urlsplit(link).hostname, "wow.breathtaking.uk")
        self.assertEqual(query["type"], ["ws"])
        self.assertEqual(query["security"], ["tls"])
        self.assertEqual(query["host"], ["wow.breathtaking.uk"])
        self.assertNotIn("sni", query)
        self.assertNotIn("pbk", query)

    def test_protocol_aware_singbox_and_clash(self) -> None:
        singbox = json.loads(_render_singbox([(self.client, self.server)], "test"))
        outbound = next(
            item
            for item in singbox["outbounds"]
            if item.get("type") == "vless" and item.get("server") == "wow.breathtaking.uk"
        )
        self.assertEqual(outbound["transport"]["type"], "ws")
        self.assertNotIn("reality", outbound["tls"])
        self.assertEqual(outbound["transport"]["headers"]["Host"], "wow.breathtaking.uk")

        clash = yaml.safe_load(_render_clash([(self.client, self.server)], "test"))
        proxy = clash["proxies"][0]
        self.assertEqual(proxy["network"], "ws")
        self.assertEqual(proxy["ws-opts"]["path"], "/internal/events/channel/stream")
        self.assertNotIn("reality-opts", proxy)


if __name__ == "__main__":
    unittest.main()

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

import yaml

from panel.app import (
    _client_connection_link,
    _render_clash,
    _render_singbox,
    _server_to_dict,
    _provision_bridge_binding,
)
from panel.models import Bridge, BridgeServerBinding, Client, Server


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
    def test_hysteria_bridge_provisions_udp_without_proxy_protocol(self) -> None:
        server = Server(id=88, name="hy2", protocol="hysteria2", public_host="exit.example.com", port=443,
                        hysteria_listen="20000-50000")
        bridge = Bridge(id=5, name="RU", public_host="bridge.example.com",
                        agent_url="http://bridge.example.com:8765", agent_token="test", enabled=True)
        with patch("panel.app.AgentClient") as agent_cls:
            agent = agent_cls.return_value
            agent.supports_udp_bridge.return_value = True
            agent.haproxy_bridges.return_value = []
            _provision_bridge_binding(bridge, server, 8443)
            agent.configure_haproxy_bridge.assert_called_once_with(
                bridge_id="bridge-5-server-88", listen_port=8443,
                target_host="exit.example.com", target_port=20000,
                send_proxy_protocol=False, protocol="udp", bandwidth_limit_mbps=0,
            )

    def test_hysteria_primary_bridge_replaces_only_dial_address(self) -> None:
        server = Server(
            id=88, name="hy2", protocol="hysteria2", mode="standalone",
            public_host="exit.example.com", port=443, sni="tls.example.com",
            hysteria_listen="20000-50000", hysteria_auth_mode="userpass",
            hysteria_obfs_type="salamander", hysteria_obfs_password="obfs-secret",
        )
        bridge = Bridge(id=5, name="RU", public_host="bridge.example.com",
                        agent_url="https://bridge.example.com:8765", agent_token="test", enabled=True)
        server.bridge_bindings = [BridgeServerBinding(
            id=12, bridge=bridge, bridge_id=5, server_id=88,
            listen_port=8443, role="primary", enabled=True,
        )]
        client = _client(server_id=88)
        link = _client_connection_link(client, server, label="hy2")
        self.assertIn("bridge.example.com:8443", link)
        self.assertIn("tls.example.com", link)
        singbox = json.loads(_render_singbox([(client, server)], "test"))
        outbound = next(row for row in singbox["outbounds"] if row["type"] == "hysteria2")
        self.assertEqual((outbound["server"], outbound["server_port"]), ("bridge.example.com", 8443))
        self.assertNotIn("server_ports", outbound)
        self.assertEqual(outbound["tls"]["server_name"], "tls.example.com")
        clash = yaml.safe_load(_render_clash([(client, server)], "test"))["proxies"][0]
        self.assertEqual((clash["server"], clash["port"]), ("bridge.example.com", 8443))
        self.assertNotIn("ports", clash)

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
            pool_tier="primary",
            in_pool=True,
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
        # Hy2 can participate in the client-side subscription pool even
        # though the Xray TCP balancer intentionally cannot dial QUIC.
        self.assertTrue(any(group.get("type") == "urltest" for group in singbox["outbounds"]))

    def test_hysteria_password_mode_uses_shared_secret_in_clients(self) -> None:
        server = Server(
            id=4,
            name="hy2-shared",
            protocol="hysteria2",
            public_host="bosska.xanka.best",
            port=22833,
            sni="bosska.xanka.best",
            dest="",
            hysteria_auth_mode="password",
            hysteria_auth_password="shared-secret",
            hysteria_obfs_type="salamander",
            hysteria_obfs_password="obfs-secret",
            hysteria_listen="22833",
        )
        client = _client(server_id=4)
        link = _client_connection_link(client, server, label="shared")
        self.assertTrue(link.startswith("hysteria2://shared-secret@"))
        self.assertIn("obfs=salamander&obfs-password=obfs-secret", link)
        self.assertNotIn("alice@example.com:", link)

        singbox = json.loads(_render_singbox([(client, server)], "shared"))
        outbound = next(item for item in singbox["outbounds"] if item["type"] == "hysteria2")
        self.assertEqual(outbound["password"], "shared-secret")

    def test_server_payload_exposes_effective_bridge_endpoint(self) -> None:
        server = Server(
            id=3,
            name="eu-vless",
            protocol="vless-reality",
            public_host="eu.example.com",
            port=443,
            sni="www.example.com",
            dest="www.example.com:443",
            bridge_enabled=True,
            bridge_public_host="ru.example.com",
            bridge_port=2443,
            mode="standalone",
        )
        payload = _server_to_dict(server)
        self.assertEqual(payload["public_host"], "eu.example.com")
        self.assertEqual(payload["client_endpoint"], "ru.example.com:2443")

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

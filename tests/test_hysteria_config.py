from __future__ import annotations

import json
import unittest
from urllib.parse import parse_qs, unquote, urlsplit

from panel.hysteria_config import (
    build_hysteria_config,
    build_hysteria_link,
    normalise_listen,
    normalise_protocol,
    parse_advanced_json,
)


class HysteriaConfigTests(unittest.TestCase):
    def test_full_acme_userpass_config(self) -> None:
        config = build_hysteria_config(
            port=443,
            listen="20000-50000",
            sni="hy2.example.com",
            tls_mode="acme",
            acme_email="admin@example.com",
            clients=[
                {"email": "alice@example.com", "password": "secret-a"},
                {"email": "bob", "id": "secret-b"},
            ],
            stats_secret="stats-secret",
            stats_port=19999,
            obfs_type="salamander",
            obfs_password="obfs-secret",
            up_mbps=250,
            down_mbps=900,
            ignore_client_bandwidth=True,
            congestion="bbr",
            bbr_profile="aggressive",
            disable_udp=True,
            udp_idle_timeout_seconds=90,
            masquerade_url="https://example.com/",
            advanced_json=json.dumps(
                {"sniff": {"enable": True}, "speedTest": True}
            ),
        )

        self.assertEqual(config["listen"], ":20000-50000")
        self.assertEqual(
            config["auth"]["userpass"]["alice@example.com"], "secret-a"
        )
        self.assertEqual(config["auth"]["userpass"]["bob"], "secret-b")
        self.assertEqual(config["acme"]["domains"], ["hy2.example.com"])
        self.assertEqual(config["trafficStats"]["listen"], "127.0.0.1:19999")
        self.assertEqual(
            config["obfs"]["salamander"]["password"], "obfs-secret"
        )
        self.assertEqual(config["bandwidth"]["up"], "250 mbps")
        self.assertEqual(config["congestion"]["bbrProfile"], "aggressive")
        self.assertTrue(config["disableUDP"])
        self.assertEqual(config["udpIdleTimeout"], "90s")
        self.assertTrue(config["sniff"]["enable"])

    def test_file_tls_requires_both_paths(self) -> None:
        with self.assertRaisesRegex(ValueError, "certificate and key"):
            build_hysteria_config(
                port=443,
                sni="hy2.example.com",
                tls_mode="files",
                cert_path="/tmp/cert.pem",
                key_path="",
                clients=[],
                stats_secret="secret",
            )

    def test_uri_uses_official_userpass_and_port_range(self) -> None:
        link = build_hysteria_link(
            username="user+mobile@example.com",
            password="p@ss:/word",
            host="2001:db8::1",
            port=443,
            listen="20000-50000",
            sni="hy2.example.com",
            label="Финляндия Hysteria",
            obfs_type="gecko",
            obfs_password="obfs & secret",
        )
        parsed = urlsplit(link)
        self.assertEqual(parsed.scheme, "hysteria2")
        self.assertEqual(parsed.hostname, "2001:db8::1")
        # urlsplit cannot represent a range as an integer port, so assert the
        # original authority/path too.
        self.assertIn("@[2001:db8::1]:20000-50000/", link)
        self.assertIn(
            "user%2Bmobile%40example.com:p%40ss%3A%2Fword@", link
        )
        query = parse_qs(parsed.query)
        self.assertEqual(query["sni"], ["hy2.example.com"])
        self.assertEqual(query["obfs"], ["gecko"])
        self.assertEqual(query["obfs-password"], ["obfs & secret"])
        self.assertEqual(unquote(parsed.fragment), "Финляндия Hysteria")

    def test_protocol_and_listen_validation(self) -> None:
        self.assertEqual(normalise_protocol("hy2"), "hysteria2")
        self.assertEqual(normalise_protocol("vless"), "vless-reality")
        self.assertEqual(normalise_listen("", fallback_port=8443), "8443")
        with self.assertRaises(ValueError):
            normalise_listen("50000-20000", fallback_port=443)
        with self.assertRaises(ValueError):
            normalise_listen("443; rm -rf /", fallback_port=443)

    def test_advanced_json_cannot_replace_managed_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "protected/unknown"):
            parse_advanced_json('{"listen":":1","auth":{"type":"password"}}')


if __name__ == "__main__":
    unittest.main()

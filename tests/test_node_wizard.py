import os
import tempfile
import types
import unittest

os.environ.setdefault("PANEL_DB_PATH", os.path.join(tempfile.gettempdir(), "xnpanel-node-wizard-test.db"))

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from panel import country_groups, tspu_check
from panel.database import Base
from panel.models import Server, Setting
from panel.schemas import EnrollmentCreateIn, SshEnrollmentCreateIn
from panel.xray_config import DEFAULT_WARP_DOMAINS, build_balancer_config, build_service_routing
from panel.xray_push import validate_service_routing_graph


class NodeWizardTests(unittest.TestCase):
    def setUp(self):
        self.engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)

    def server(self, db, name, download, upload, cores=2, memory_gib=2, latency=30):
        row = Server(
            name=name, display_name=name, folder="Нидерланды",
            agent_url=f"http://{name}:8765", agent_token="token",
            public_host="1.1.1.1", port=443, sni="example.com",
            dest="example.com:443", private_key="private", public_key="public",
            short_id="abcd", mode="standalone", protocol="vless-reality",
            speed_download_mbps=download, speed_upload_mbps=upload,
            speed_latency_ms=latency, node_cpu_count=cores,
            node_mem_total_bytes=memory_gib * 2**30,
        )
        db.add(row)
        db.flush()
        return row

    def test_folder_uses_one_strongest_gateway_and_no_fallback(self):
        with self.Session() as db:
            slow = self.server(db, "nl-1", 100, 100)
            fast = self.server(db, "nl-2", 900, 700, cores=4, memory_gib=8, latency=20)
            medium = self.server(db, "nl-3", 300, 250)
            result = country_groups.reconcile_folder_group(db, "Нидерланды")
            db.commit()
            self.assertEqual(result["gateway_id"], fast.id)
            rows = db.scalars(select(Server).order_by(Server.id)).all()
            self.assertEqual([r.id for r in rows if r.folder_gateway], [fast.id])
            self.assertTrue(all(r.subscription_visible for r in rows))
            self.assertTrue(all(r.mode == "standalone" for r in rows))
            self.assertTrue(all(r.pool_tier != "fallback" for r in rows))
            self.assertTrue(all(r.balance_group == "folder:нидерланды" for r in rows))
            self.assertFalse(slow.in_pool or medium.in_pool or fast.in_pool)
            self.assertEqual(fast.display_name, "nl-2")

    def test_blocked_gateway_is_ungrouped_and_replaced(self):
        with self.Session() as db:
            first = self.server(db, "nl-1", 900, 900)
            second = self.server(db, "nl-2", 500, 500)
            country_groups.reconcile_folder_group(db, "Нидерланды")
            first.tspu_blocked = True
            country_groups.reconcile_folder_group(db, "Нидерланды")
            db.commit()
            self.assertTrue(first.subscription_visible)
            self.assertFalse(first.folder_gateway)
            self.assertEqual(first.balance_group, "")
            self.assertEqual(second.mode, "standalone")
            self.assertTrue(second.subscription_visible)

    def test_base_nodes_join_country_config_without_entering_global_primary(self):
        with self.Session() as db:
            base = self.server(db, "fi-base", 900, 900)
            base.tags = '["base"]'
            premium = self.server(db, "fi-premium", 500, 500)
            premium.folder = base.folder = "Финляндия"
            result = country_groups.reconcile_folder_group(db, "Финляндия")
            db.commit()
            self.assertIsNotNone(result["gateway_id"])
            self.assertEqual(base.balance_group, "folder:финляндия")
            self.assertEqual(premium.balance_group, "folder:финляндия")
            self.assertFalse(base.in_pool)
            self.assertEqual(base.pool_tier, "")
            self.assertTrue(base.subscription_visible)
            self.assertTrue(premium.subscription_visible)

    def test_weighted_balancer_config_contains_local_and_peer_costs(self):
        config = build_balancer_config(
            port=443, server_names=["example.com"], dest="example.com:443",
            private_key="private", short_ids=["abcd"],
            clients=[{"id": "11111111-1111-1111-1111-111111111111", "email": "u", "flow": "xtls-rprx-vision"}],
            upstreams=[
                {"id": 1, "local": True, "tier": "primary", "routing_weight": 4.0},
                {"id": 2, "public_host": "1.1.1.1", "port": 443, "sni": "example.com",
                 "public_key": "public", "short_id": "abcd",
                 "auth_uuid": "22222222-2222-2222-2222-222222222222",
                 "tier": "primary", "routing_weight": 1.0, "ip_region": {}},
            ],
            service_routing_services=set(),
        )
        tags = {item["tag"]: item["protocol"] for item in config["outbounds"]}
        self.assertEqual(tags["pool-1"], "freedom")
        self.assertEqual(tags["pool-2"], "vless")
        costs = config["routing"]["balancers"][0]["strategy"]["settings"]["costs"]
        self.assertEqual(costs, [{"match": "pool-1", "value": 0.25}, {"match": "pool-2", "value": 1.0}])
        self.assertFalse(any("fb" in item["match"] for item in costs))

    def test_service_only_peer_is_not_in_country_pool(self):
        config = build_balancer_config(
            port=443, server_names=["example.com"], dest="example.com:443",
            private_key="private", short_ids=["abcd"], clients=[],
            upstreams=[
                {"id": 1, "local": True, "tier": "primary", "routing_weight": 2.0},
                {"id": 2, "public_host": "1.1.1.1", "port": 443,
                 "sni": "example.com", "public_key": "public", "short_id": "abcd",
                 "auth_uuid": "22222222-2222-2222-2222-222222222222",
                 "pool_enabled": False,
                 "ip_region": {"results": {"custom": [
                     {"service": "Gemini supported", "ipv4": "Yes"},
                 ]}}},
            ],
            service_routing_services={"gemini"},
        )
        tags = {item["tag"] for item in config["outbounds"]}
        self.assertIn("svc-gemini-p-2", tags)
        self.assertNotIn("pool-2", tags)
        costs = config["routing"]["balancers"][0]["strategy"]["settings"]["costs"]
        self.assertEqual(costs, [{"match": "pool-1", "value": 0.5}])

    def test_standalone_service_balancers_select_their_service_outbounds(self):
        outbounds = []
        balancers, selectors, rules, handled = build_service_routing(
            outbounds=outbounds,
            upstreams=[
                {
                    "id": 64, "public_host": "1.1.1.1", "port": 443,
                    "sni": "example.com", "public_key": "public",
                    "short_id": "abcd",
                    "auth_uuid": "22222222-2222-2222-2222-222222222222",
                    "ip_region": {"results": {"custom": [
                        {"service": "YouTube", "ipv4": "RU"},
                    ]}},
                },
                {
                    "id": 62, "public_host": "2.2.2.2", "port": 443,
                    "sni": "example.com", "public_key": "public",
                    "short_id": "abcd",
                    "auth_uuid": "33333333-3333-3333-3333-333333333333",
                    "ip_region": {"results": {"custom": [
                        {"service": "Gemini Supported", "ipv4": "Yes"},
                    ]}},
                },
            ],
            local_ip_region={"results": {"custom": [
                {"service": "YouTube", "ipv4": "GB"},
                {"service": "Gemini Supported", "ipv4": "No"},
            ]}},
            enabled_services={"youtube", "gemini"},
            source_server_id=86,
        )
        by_tag = {item["tag"]: item for item in balancers}
        self.assertEqual(
            by_tag["service-youtube-balancer"]["selector"],
            ["svc-youtube-"],
        )
        self.assertEqual(
            by_tag["service-gemini-balancer"]["selector"],
            ["svc-gemini-"],
        )
        self.assertIn("svc-youtube-64", {item["tag"] for item in outbounds})
        self.assertIn("svc-gemini-62", {item["tag"] for item in outbounds})
        self.assertEqual(set(selectors), {"svc-youtube-", "svc-gemini-"})
        self.assertEqual(handled, {"youtube", "gemini"})
        self.assertEqual(
            {rule.get("balancerTag") for rule in rules},
            {"service-youtube-balancer", "service-gemini-balancer"},
        )

    def test_service_routing_uses_strongest_verified_peer_and_complete_youtube_set(self):
        outbounds = []
        balancers, _selectors, rules, _handled = build_service_routing(
            outbounds=outbounds,
            upstreams=[
                {"id": 1, "public_host": "1.1.1.1", "port": 443,
                 "sni": "one.example", "public_key": "public", "short_id": "abcd",
                 "auth_uuid": "11111111-1111-1111-1111-111111111111",
                 "routing_weight": 1.0, "stability_score": 1.0,
                 "ip_region": {"results": {"custom": [{"service": "YouTube", "ipv4": "RU"}]}}},
                {"id": 2, "public_host": "2.2.2.2", "port": 443,
                 "sni": "two.example", "public_key": "public", "short_id": "abcd",
                 "auth_uuid": "22222222-2222-2222-2222-222222222222",
                 "routing_weight": 4.0, "stability_score": 0.99,
                 "ip_region": {"results": {"custom": [{"service": "YouTube", "ipv4": "RU"}]}}},
            ],
            local_ip_region={"results": {"custom": [{"service": "YouTube", "ipv4": "CZ"}]}},
            enabled_services={"youtube"},
            source_server_id=99,
        )
        self.assertEqual({item["tag"] for item in outbounds}, {"svc-youtube-2"})
        youtube_rule = next(rule for rule in rules if rule.get("balancerTag") == "service-youtube-balancer")
        self.assertIn("geosite:youtube", youtube_rule["domain"])
        self.assertIn("domain:doubleclick.net", youtube_rule["domain"])
        self.assertIn("domain:googlesyndication.com", youtube_rule["domain"])
        validate_service_routing_graph({"outbounds": outbounds, "routing": {"balancers": balancers, "rules": rules}})

    def test_hysteria_wire_check_does_not_force_a_tcp_port(self):
        hysteria = types.SimpleNamespace(protocol="hysteria2", port=443)
        self.assertIsNone(tspu_check._latency_lab_tcp_port(hysteria))
        vless = types.SimpleNamespace(protocol="vless-reality", port=8443)
        self.assertEqual(tspu_check._latency_lab_tcp_port(vless), 8443)

    def test_new_ssh_addons_are_opt_in_and_warp_defaults_are_exact(self):
        body = SshEnrollmentCreateIn(
            enrollment=EnrollmentCreateIn(name="auto"),
            ssh_host="203.0.113.10",
            ssh_password="one-time",
        )
        self.assertFalse(body.install_traffic_guard)
        self.assertFalse(body.install_warp)
        self.assertEqual(body.traffic_guard_profile, "scanner")
        self.assertEqual(DEFAULT_WARP_DOMAINS[-3:], [
            "domain:2ip.io", "domain:2ip.ua", "domain:check-host.net",
        ])
        self.assertNotIn("domain:google.com", DEFAULT_WARP_DOMAINS)

    def test_service_routing_validation_rejects_orphan_selector(self):
        with self.assertRaisesRegex(ValueError, "no matching outbound"):
            validate_service_routing_graph({
                "outbounds": [{"tag": "svc-youtube-1", "protocol": "vless"}],
                "routing": {"balancers": [{"tag": "service-youtube-balancer", "selector": ["pool-"]}], "rules": []},
            })

    def test_wire_parser_and_country_prefix(self):
        self.assertTrue(tspu_check.parse_latency_lab_wire({
            "ok": True,
            "result": {"wire_precheck": True, "wire_ok": True},
        }))
        self.assertFalse(tspu_check.parse_latency_lab_wire({
            "ok": True,
            "result": {"wire_precheck": True, "wire_ok": False},
        }))
        with self.assertRaises(ValueError):
            tspu_check.parse_latency_lab_wire({
                "ok": True,
                "result": {"results": [{"operator": "mts", "ok": True}]},
            })
        self.assertEqual(country_groups.match_country("Нидер"), ("NL", "Нидерланды"))

    def test_latency_lab_account_counter_parser_is_strict(self):
        self.assertEqual(
            tspu_check.parse_latency_lab_account_used(
                {"ok": True, "result": {"window": {"used": 41, "limit": 100}}}
            ),
            41,
        )
        with self.assertRaises(ValueError):
            tspu_check.parse_latency_lab_account_used(
                {"ok": True, "result": {"day": {"total": 41}}}
            )

    def test_daily_quota_keeps_urgent_reserve(self):
        original_session = tspu_check.SessionLocal
        original_limit = tspu_check.LATENCY_LAB_DAILY_LIMIT
        original_reserve = tspu_check.LATENCY_LAB_RESERVED_URGENT
        try:
            tspu_check.SessionLocal = self.Session
            tspu_check.LATENCY_LAB_DAILY_LIMIT = 100
            tspu_check.LATENCY_LAB_RESERVED_URGENT = 25
            status = tspu_check.seed_latency_lab_used(25)
            self.assertEqual(status["used"], 25)
            self.assertEqual(status["remaining_scheduled"], 50)
            self.assertEqual(status["remaining_total"], 75)
            for _ in range(50):
                tspu_check._claim_latency_lab_request("scheduled")
            with self.assertRaises(RuntimeError):
                tspu_check._claim_latency_lab_request("scheduled")
            tspu_check._claim_latency_lab_request("online_drop")
            self.assertEqual(tspu_check.latency_lab_quota_status()["used"], 76)
        finally:
            tspu_check.SessionLocal = original_session
            tspu_check.LATENCY_LAB_DAILY_LIMIT = original_limit
            tspu_check.LATENCY_LAB_RESERVED_URGENT = original_reserve


if __name__ == "__main__":
    unittest.main()

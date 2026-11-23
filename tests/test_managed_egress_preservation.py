from copy import deepcopy
import unittest

from agent.managed_egress import LOCAL_OUTBOUND, preserve_local_egress


class EgressPreservationTests(unittest.TestCase):
    def test_preserves_catch_all_and_leaves_service_rules_unchanged(self):
        special = {"type": "field", "domain": ["domain:example.org"], "network": "tcp,udp", "outboundTag": "direct"}
        local = {"tag": LOCAL_OUTBOUND, "protocol": "socks", "settings": {"servers": [{"address": "192.0.2.3", "port": 8080}]}}
        active = {
            "outbounds": [local],
            "routing": {"rules": [{"type": "field", "network": "tcp,udp", "outboundTag": LOCAL_OUTBOUND}]},
        }
        incoming = {
            "outbounds": [{"protocol": "freedom", "tag": "direct"}],
            "routing": {"rules": [deepcopy(special), {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}]},
        }
        preserve_local_egress(incoming, active)
        preserve_local_egress(incoming, active)
        self.assertEqual(incoming["routing"]["rules"][0], special)
        self.assertEqual(incoming["routing"]["rules"][-1]["outboundTag"], LOCAL_OUTBOUND)
        self.assertEqual(incoming["outbounds"].count(local), 1)
        self.assertIsNot(incoming["outbounds"][-1], local)

    def test_no_local_mode_without_an_active_managed_route(self):
        config = {"outbounds": [], "routing": {"rules": [{"network": "tcp,udp", "outboundTag": "direct"}]}}
        before = deepcopy(config)
        preserve_local_egress(config, {})
        self.assertEqual(config, before)

    def test_scoped_policy_cannot_replace_an_unscoped_direct_rule(self):
        scope = {"type": "field", "inboundTag": ["vless-reality"], "network": "tcp,udp", "outboundTag": LOCAL_OUTBOUND}
        outgoing = {"type": "field", "network": "tcp,udp", "outboundTag": "direct"}
        before = {"outbounds": [{"tag": LOCAL_OUTBOUND, "protocol": "socks"}],
                  "routing": {"rules": [scope]}}
        incoming = {"inbounds": [{"tag": "vless-reality"}, {"tag": "another"}],
                    "routing": {"rules": [deepcopy(outgoing)]}, "outbounds": []}
        preserve_local_egress(incoming, before)
        self.assertEqual(incoming["routing"]["rules"], [scope, outgoing])

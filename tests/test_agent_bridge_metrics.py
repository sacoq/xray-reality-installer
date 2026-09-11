from __future__ import annotations

import unittest

from agent import agent


class BridgeMetricsTests(unittest.TestCase):
    def test_parses_listener_traffic_and_backend_health(self) -> None:
        payload = "\n".join(
            [
                "# pxname,svname,scur,stot,bin,bout,status,check_status,lastchg,",
                "bridge_in,FRONTEND,3,18,1234,5678,OPEN,,42,",
                "eu_target,target,1,18,0,0,UP,L7OK,7,",
            ]
        )

        result = agent._parse_haproxy_bridge_stats(payload)

        self.assertEqual(result["current_connections"], 3)
        self.assertEqual(result["total_connections"], 18)
        self.assertEqual(result["bytes_in"], 1234)
        self.assertEqual(result["bytes_out"], 5678)
        self.assertTrue(result["backend_connected"])
        self.assertEqual(result["backend_status"], "UP")
        self.assertEqual(result["backend_check_status"], "L7OK")

    def test_backend_down_is_reported_even_when_listener_is_open(self) -> None:
        payload = "\n".join(
            [
                "# pxname,svname,scur,stot,bin,bout,status,check_status,lastchg,",
                "bridge_in,FRONTEND,0,2,10,20,OPEN,,100,",
                "eu_target,target,0,2,0,0,DOWN,L4TOUT,12,",
            ]
        )

        result = agent._parse_haproxy_bridge_stats(payload)

        self.assertFalse(result["backend_connected"])
        self.assertEqual(result["backend_status"], "DOWN")
        self.assertEqual(result["backend_check_status"], "L4TOUT")

    def test_renders_bidirectional_per_port_rate_limit(self) -> None:
        script = agent._render_bridge_tc_script(
            listen_port=8443, limit_mbps=100
        )

        self.assertIn("PORT=8443", script)
        self.assertIn("RATE=100", script)
        self.assertIn('dst_port "$PORT"', script)
        self.assertIn('src_port "$PORT"', script)


if __name__ == "__main__":
    unittest.main()

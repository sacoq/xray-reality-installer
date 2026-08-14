from __future__ import annotations

import unittest
from unittest.mock import patch

from panel import xray_config


class GeminiEgressTests(unittest.TestCase):
    def test_stable_egress_precedes_warp_and_blocks_quic(self) -> None:
        outbounds = [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ]
        rules: list[dict] = []
        with (
            patch.object(xray_config, "GEMINI_EGRESS_HOST", "203.0.113.10"),
            patch.object(xray_config, "GEMINI_EGRESS_PORT", 15443),
        ):
            xray_config.apply_warp_config(
                outbounds,
                rules,
                enabled=True,
                domains=["domain:gemini.google.com"],
            )
        self.assertEqual(outbounds[0]["tag"], "gemini-egress")
        self.assertEqual(rules[0]["outboundTag"], "gemini-egress")
        self.assertEqual(rules[0]["network"], "tcp")
        self.assertEqual(rules[1]["outboundTag"], "blocked")
        self.assertEqual(rules[1]["network"], "udp")
        self.assertEqual(rules[2]["outboundTag"], "warp-out")

    def test_reconcile_is_idempotent(self) -> None:
        outbounds = [
            {"tag": "direct", "protocol": "freedom"},
            {"tag": "blocked", "protocol": "blackhole"},
        ]
        rules: list[dict] = []
        with patch.object(xray_config, "GEMINI_EGRESS_HOST", "203.0.113.10"):
            for _ in range(2):
                xray_config.apply_warp_config(
                    outbounds,
                    rules,
                    enabled=True,
                    domains=["domain:gemini.google.com"],
                )
        self.assertEqual(
            sum(item.get("tag") == "gemini-egress" for item in outbounds), 1
        )
        self.assertEqual(
            sum(item.get("outboundTag") == "gemini-egress" for item in rules), 1
        )


if __name__ == "__main__":
    unittest.main()

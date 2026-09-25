"""Regression checks for the TSPU entry points used by the panel."""

import inspect
import types
import unittest

from panel import tspu_check


class TspuCheckContractTests(unittest.TestCase):
    def test_manual_and_ssh_admission_reasons_are_accepted(self):
        signature = inspect.signature(tspu_check.check_server_now)
        signature.bind(1, reason="manual")
        signature.bind(1, reason="ssh_admission")

    def test_hysteria_does_not_advertise_udp_port_as_tcp(self):
        hysteria = types.SimpleNamespace(protocol="hysteria2", port=1337)
        vless = types.SimpleNamespace(protocol="vless", port=8443)
        self.assertIsNone(tspu_check._latency_lab_tcp_port(hysteria))
        self.assertEqual(tspu_check._latency_lab_tcp_port(vless), 8443)

    def test_wire_verdict_requires_explicit_wire_precheck(self):
        self.assertTrue(tspu_check.parse_latency_lab_wire({
            "ok": True, "result": {"wire_precheck": True, "wire_ok": True},
        }))
        with self.assertRaises(ValueError):
            tspu_check.parse_latency_lab_wire({
                "ok": True, "result": {"wire_ok": True},
            })


if __name__ == "__main__":
    unittest.main()

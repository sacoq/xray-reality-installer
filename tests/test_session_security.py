from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import agent
from agent.session_security import (
    SessionTracker,
    group_network_points,
    is_probe_destination,
    parse_xray_access_line,
    same_network_point,
)


class NetworkPointTests(unittest.TestCase):
    def test_any_two_matching_ipv4_octets_are_one_point(self) -> None:
        self.assertTrue(same_network_point("93.150.13.1", "93.150.49.2"))
        self.assertTrue(same_network_point("44.150.49.9", "93.150.49.2"))
        self.assertTrue(same_network_point("44.22.7.9", "44.150.49.9"))
        self.assertFalse(same_network_point("1.2.3.4", "5.6.3.8"))

    def test_grouping_uses_transitive_closure(self) -> None:
        groups = group_network_points(
            ["93.150.13.1", "93.150.49.2", "44.150.49.9", "8.8.8.8"]
        )
        self.assertEqual(len(groups), 2)
        self.assertIn(
            ["44.150.49.9", "93.150.13.1", "93.150.49.2"], groups
        )

    def test_ipv6_privacy_addresses_use_a_48_prefix(self) -> None:
        self.assertTrue(
            same_network_point("2606:4700:4700::1111", "2606:4700:4700::1001")
        )
        self.assertFalse(
            same_network_point("2606:4700:4700::1111", "2606:4700:4701::1111")
        )


class AccessParserTests(unittest.TestCase):
    def test_xray_access_line_is_parsed(self) -> None:
        parsed = parse_xray_access_line(
            "2026/08/03 11:22:33 from 8.8.8.8:54321 accepted "
            "tcp:example.com:443 [vless-reality -> direct] email: Sub_User"
        )
        self.assertEqual(
            parsed,
            {
                "identity": "sub_user",
                "source_ip": "8.8.8.8",
                "destination": "example.com:443",
            },
        )

    def test_probe_destinations_are_recognised(self) -> None:
        self.assertTrue(is_probe_destination("connectivitycheck.gstatic.com:443"))
        self.assertTrue(is_probe_destination("internet.yandex.ru:443"))
        self.assertFalse(is_probe_destination("example.com:443"))


class TrackerTests(unittest.TestCase):
    def test_probe_only_activity_is_not_counted(self) -> None:
        tracker = SessionTracker(retention_seconds=3600)
        self.assertFalse(
            tracker.record(
                identity="user",
                source_ip="8.8.8.8",
                protocol="vless",
                destination="www.gstatic.com:443",
                timestamp=1000,
            )
        )
        snapshot = tracker.snapshot(now=1001, window_seconds=300)
        self.assertEqual(snapshot["clients"], [])
        self.assertEqual(snapshot["ignored_probe_events"], 1)

    def test_snapshot_groups_sources_per_identity(self) -> None:
        tracker = SessionTracker(retention_seconds=3600)
        for ip in ("93.150.13.1", "93.150.49.2", "1.1.1.1"):
            tracker.record(
                identity="Sub_A",
                source_ip=ip,
                protocol="vless",
                destination="example.com:443",
                timestamp=1000,
            )
        snapshot = tracker.snapshot(now=1010, window_seconds=300)
        self.assertEqual(len(snapshot["clients"]), 1)
        row = snapshot["clients"][0]
        self.assertEqual(row["identity"], "sub_a")
        self.assertEqual(row["raw_ip_count"], 3)
        self.assertEqual(row["point_count"], 2)

    def test_min_events_filters_one_off_sources(self) -> None:
        tracker = SessionTracker(retention_seconds=3600)
        tracker.record(
            identity="user",
            source_ip="8.8.8.8",
            protocol="hysteria2",
            timestamp=1000,
        )
        self.assertEqual(
            tracker.snapshot(now=1001, window_seconds=300, min_events=2)["clients"],
            [],
        )


class AccessLogPermissionsTests(unittest.TestCase):
    def test_agent_hands_tmpfs_log_to_xray_service_account(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "xray-access.log"
            with (
                patch.object(agent, "XRAY_ACCESS_LOG", path),
                patch.object(agent, "_xray_service_uid_gid", return_value=(123, 456)),
                patch.object(agent.os, "chown", create=True) as chown,
                patch.object(agent.os, "chmod") as chmod,
            ):
                agent._prepare_xray_access_log()

            self.assertTrue(path.is_file())
            chown.assert_called_once_with(path, 123, 456)
            chmod.assert_called_once_with(path, 0o666)


if __name__ == "__main__":
    unittest.main()

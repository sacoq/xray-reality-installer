import io
import ipaddress
import unittest
from unittest.mock import patch
from agent import traffic_guard as guard


class TrafficGuardSafetyTests(unittest.TestCase):
    def test_extended_download_merges_both_lists(self):
        with patch.object(guard.urllib.request, 'urlopen', side_effect=[io.BytesIO(b'192.0.2.0/24\n'), io.BytesIO(b'2001:db8::/32\n')]) as fetch:
            networks = guard.download('extended')
        self.assertEqual(len(networks), 2)
        self.assertEqual(fetch.call_count, 2)

    def test_empty_or_default_route_list_is_rejected(self):
        for content in (b'', b'0.0.0.0/0\n', b'not a network\n'):
            with self.subTest(content=content), patch.object(guard.urllib.request, 'urlopen', return_value=io.BytesIO(content)):
                with self.assertRaises(ValueError): guard.download('scanner')

    def test_management_overlap_rejected_before_any_command(self):
        with patch.object(guard, 'download', return_value=[ipaddress.ip_network('192.0.2.0/24')]), patch.object(guard, 'run') as run:
            with self.assertRaises(ValueError): guard.install('extended', True, ['192.0.2.5'])
            run.assert_not_called()

    def test_rules_never_modify_unrelated_firewall(self):
        with patch.object(guard, 'run') as run:
            run.return_value.returncode=1
            guard.configure_rules(True)
        commands=[call.args[0] for call in run.call_args_list]
        self.assertTrue(any('-I' in c and 'INPUT' in c for c in commands))
        self.assertFalse(any('ufw' in c or 'FORWARD' in c or '-P' in c or '-F' in c for c in commands))
        self.assertTrue(all(c[0] in ('iptables','ip6tables') for c in commands))


if __name__ == '__main__': unittest.main()

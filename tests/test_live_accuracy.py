import unittest
from unittest.mock import patch
from agent import agent


class LiveAccuracyTests(unittest.TestCase):
    def test_pings_and_single_burst_are_not_activity(self):
        self.assertFalse(agent._meaningful_activity([(100,4000),(105,4000)],105))
        self.assertFalse(agent._meaningful_activity([(100,50000)],105))
        self.assertTrue(agent._meaningful_activity([(100,10000),(105,10000)],105))
        self.assertFalse(agent._meaningful_activity([(40,10000),(105,10000)],105))

    def test_reset_is_not_rate(self):
        self.assertEqual(agent._counter_delta(100,10000000),0)

    def test_first_sample_never_counts_historical_clients(self):
        with patch.object(agent,'_live_snapshot',agent._LiveSnapshot()), \
             patch.object(agent,'_collect_user_stats',return_value={'old':{'up':10**9,'down':10**9}}), \
             patch.object(agent,'_net_interface_counters',return_value={'eth0':(10**9,10**9)}), \
             patch.object(agent,'_cpu_percent',return_value=0), patch.object(agent,'_collect_sysinfo',return_value={}):
            agent._sample_live_once()
            self.assertEqual(agent._live_snapshot.last_active,{})
            self.assertEqual(agent._live_snapshot.net_rx_bps,0)
            self.assertEqual(agent._live_snapshot.rates['old']['down_bps'],0)

    def test_tunnels_and_loopback_are_not_counted_twice(self):
        raw='header\nheader\n'+''.join(f'{name}: {rx} 0 0 0 0 0 0 0 {rx} 0\n' for name,rx in [('eth0',100),('lo',999),('warp',500),('wg0',500),('veth123',500),('tun0',500)])
        with patch.object(agent,'_read_proc',side_effect=lambda p: raw if p=='/proc/net/dev' else '1'), patch.object(agent.Path,'exists',return_value=False):
            self.assertEqual(agent._net_counters(),(100,100))

    def test_global_ipv4_list_keeps_all_public_addresses(self):
        output = (
            '2: eth0    inet 91.245.226.179/24 brd 91.245.226.255 scope global eth0\n'
            '2: eth0    inet 91.245.226.180/24 brd 91.245.226.255 scope global secondary eth0\n'
            '2: eth0    inet 91.245.226.181/24 brd 91.245.226.255 scope global secondary eth0\n'
        )
        with patch.object(agent, '_run', return_value=type('R', (), {'stdout': output})()):
            self.assertEqual(
                agent._global_ipv4_addresses(),
                ['91.245.226.179', '91.245.226.180', '91.245.226.181'],
            )

    def test_firewall_port_status_is_bounded_to_requested_port(self):
        def fake_run(command, **_kwargs):
            if command[:2] == ['ss', '-lnt']:
                return type('R', (), {'stdout': 'LISTEN 0 4096 0.0.0.0:443 0.0.0.0:*\n'})()
            if command[:3] == ['iptables', '-S', 'INPUT']:
                return type('R', (), {'stdout': '-P INPUT DROP\n-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 22 -j ACCEPT\n'})()
            raise AssertionError(command)
        with patch.object(agent, '_run', side_effect=fake_run), patch.object(agent.shutil, 'which', return_value=None):
            status = agent.firewall_tcp_status(port=443)
        self.assertTrue(status.listening)
        self.assertEqual(status.input_policy, 'DROP')
        self.assertEqual(status.matching_rules, ['-A INPUT -p tcp -m tcp --dport 443 -j ACCEPT'])


if __name__=='__main__':unittest.main()

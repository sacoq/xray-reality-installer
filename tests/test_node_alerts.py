import unittest
from panel.node_alerts import evaluate
from panel.schemas import NotificationPreferences


class NodeAlertTests(unittest.TestCase):
    def setUp(self):
        self.state={};self.now=10000;self.events=[];self.prefs=NotificationPreferences().model_dump()
    def sample(self,count=100,online=True,pressure=10):
        self.now+=60
        self.state,events=evaluate(self.state,now=self.now,online=online,count=count,pressure=pressure,prefs=self.prefs)
        self.events.extend(action for action,_ in events)
    def test_drop_debounce_and_recovery(self):
        for _ in range(4):self.sample()
        self.sample(20);self.sample(20);self.assertEqual(self.events,[])
        self.sample(20);self.assertEqual(self.events,['server.online_drop'])
        for _ in range(6):self.sample(20)
        self.assertEqual(len(self.events),1)
        for _ in range(3):self.sample(90)
        self.assertEqual(self.events,['server.online_drop','server.online_recovery'])
    def test_unknown_is_not_zero_and_flap_does_not_alert(self):
        for _ in range(4):self.sample()
        for _ in range(4):self.sample(None)
        self.sample(20)
        self.sample(online=False);self.sample(online=False);self.sample()
        self.assertEqual(self.events,[])
    def test_down_up_state_persists(self):
        for _ in range(3):self.sample(online=False)
        self.assertEqual(self.events,['server.offline'])
        for _ in range(3):self.sample()
        self.assertEqual(self.events,['server.offline','server.online'])
    def test_small_online_not_alerted(self):
        for _ in range(4):self.sample(4)
        for _ in range(5):self.sample(0)
        self.assertEqual(self.events,[])


if __name__=='__main__':unittest.main()

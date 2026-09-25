import ast
import unittest
from pathlib import Path


SOURCE = (Path(__file__).parents[1] / 'agent' / 'agent.py').read_text(encoding='utf-8')
TREE = ast.parse(SOURCE)
HELPER = next(node for node in TREE.body if isinstance(node, ast.FunctionDef)
              and node.name == '_public_sni_https_available')


class PublicSniHttpsTests(unittest.TestCase):
    def check(self, vpn_port, listeners='', xray_ports=(), hysteria=False, agent_port=8765):
        namespace = {
            'AGENT_PORT': agent_port,
            '_tcp_listeners': lambda port: listeners,
            '_xray_inbound_ports': lambda: set(xray_ports),
            '_port_in_hysteria_listen': lambda port: hysteria,
        }
        exec(compile(ast.Module(body=[HELPER], type_ignores=[]), '<agent>', 'exec'), namespace)
        return namespace['_public_sni_https_available'](vpn_port)

    def test_nginx_and_free_port_can_serve_public_https(self):
        self.assertTrue(self.check(8443))
        self.assertTrue(self.check(8443, 'LISTEN nginx'))

    def test_existing_non_nginx_or_vpn_port_is_preserved(self):
        self.assertFalse(self.check(443))
        self.assertFalse(self.check(8443, xray_ports={443}))
        self.assertFalse(self.check(8443, hysteria=True))
        self.assertFalse(self.check(8443, listeners='LISTEN nginx\nLISTEN caddy'))
        self.assertFalse(self.check(8443, agent_port=443))


if __name__ == '__main__':
    unittest.main()

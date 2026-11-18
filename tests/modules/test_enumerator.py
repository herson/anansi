import unittest

from domain.findings import Finding
from modules.enumerator import ServiceEnumerator


class TestServiceEnumerator(unittest.TestCase):

    def test_returns_one_finding_per_host_port_and_protocol(self):
        scan_data = {'scan': {'192.168.1.1': {
            'tcp': {80: {'name': 'http', 'product': 'Apache httpd', 'version': '2.4.49'}},
            'udp': {53: {'name': 'domain', 'product': 'ISC BIND', 'version': '9.11.5'}},
        }}}
        self.assertEqual(ServiceEnumerator(scan_data).enumerate(), [
            Finding('192.168.1.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49'),
            Finding('192.168.1.1', 53, 'udp', 'domain', 'ISC BIND', '9.11.5'),
        ])

    def test_same_port_on_different_hosts_is_kept_for_each_host(self):
        scan_data = {'scan': {
            '10.0.0.1': {'tcp': {80: {'name': 'http', 'product': 'Apache httpd', 'version': '2.4.49'}}},
            '10.0.0.2': {'tcp': {80: {'name': 'http', 'product': 'nginx', 'version': '1.18.0'}}},
        }}
        findings = ServiceEnumerator(scan_data).enumerate()
        self.assertEqual({(f.host, f.port, f.product) for f in findings}, {
            ('10.0.0.1', 80, 'Apache httpd'),
            ('10.0.0.2', 80, 'nginx'),
        })

    def test_same_port_on_tcp_and_udp_is_kept_for_each_protocol(self):
        scan_data = {'scan': {'10.0.0.1': {
            'tcp': {53: {'name': 'domain', 'version': ''}},
            'udp': {53: {'name': 'domain', 'version': ''}},
        }}}
        findings = ServiceEnumerator(scan_data).enumerate()
        self.assertEqual(sorted(f.protocol for f in findings), ['tcp', 'udp'])

    def test_missing_product_becomes_empty_string(self):
        scan_data = {'scan': {'10.0.0.1': {'tcp': {22: {'name': 'ssh', 'version': '8.2'}}}}}
        self.assertEqual(ServiceEnumerator(scan_data).enumerate()[0].product, '')

    def test_ignores_non_port_sections_of_a_host(self):
        scan_data = {'scan': {'10.0.0.1': {
            'hostnames': [{'name': '', 'type': ''}],
            'status': {'state': 'up'},
            'tcp': {22: {'name': 'ssh', 'version': '8.2'}},
        }}}
        self.assertEqual(len(ServiceEnumerator(scan_data).enumerate()), 1)

    def test_empty_or_missing_scan_data_gives_no_findings(self):
        self.assertEqual(ServiceEnumerator({'scan': {}}).enumerate(), [])
        self.assertEqual(ServiceEnumerator({}).enumerate(), [])


if __name__ == '__main__':
    unittest.main()

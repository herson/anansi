import unittest
from modules.enumerator import ServiceEnumerator

class TestServiceEnumerator(unittest.TestCase):

    def setUp(self):
        # Sample scan data for testing
        self.scan_data = {
            'scan': {
                '192.168.1.1': {
                    'tcp': {
                        80: {'name': 'http', 'version': '1.1'},
                        22: {'name': 'ssh', 'version': 'OpenSSH 7.9'},
                    },
                    'udp': {
                        53: {'name': 'dns', 'version': '9.11.5'},
                    }
                },
                '192.168.1.2': {
                    'tcp': {
                        443: {'name': 'https', 'version': '1.1'},
                    }
                }
            }
        }
        self.enumerator = ServiceEnumerator(self.scan_data)

    def test_enumerate_services(self):
        expected_services = {
            80: {'service': 'http', 'version': '1.1'},
            22: {'service': 'ssh', 'version': 'OpenSSH 7.9'},
            53: {'service': 'dns', 'version': '9.11.5'},
            443: {'service': 'https', 'version': '1.1'},
        }
        services = self.enumerator.enumerate()
        self.assertEqual(services, expected_services)

    def test_empty_scan_data(self):
        empty_enumerator = ServiceEnumerator({'scan': {}})
        services = empty_enumerator.enumerate()
        self.assertEqual(services, {})

if __name__ == '__main__':
    unittest.main()


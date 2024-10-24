# test_scanner.py
import unittest
from unittest.mock import patch

@patch('modules.scanner.nmap')
class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        from modules.scanner import NetworkScanner  # Import here to ensure nmap is mocked
        self.scanner = NetworkScanner("127.0.0.1", 4)

    def test_initialization(self, mock_nmap):
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.threads, 4)

    def test_scan(self, mock_nmap):
        # This test would require mocking the nmap.PortScanner
        # to avoid actual network calls.
        pass  # Implement your test logic here

if __name__ == '__main__':
    unittest.main()

# test_scanner.py
import unittest
from modules.scanner import NetworkScanner  # Changed to absolute import

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        self.scanner = NetworkScanner("127.0.0.1", 4)

    def test_initialization(self):
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.threads, 4)

    def test_scan(self):
        # This test would require mocking the nmap.PortScanner
        # to avoid actual network calls.
        pass  # Implement your test logic here

if __name__ == '__main__':
    unittest.main()

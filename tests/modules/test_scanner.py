import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub the nmap C-extension before any project import touches it
sys.modules.setdefault('nmap', MagicMock())


class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        # Patch PortScanner itself: the module-level stub above is skipped when
        # another test (e.g. the real-nmap integration test) imported nmap first.
        port_scanner = patch('modules.scanner.nmap.PortScanner', side_effect=lambda: MagicMock())
        port_scanner.start()
        self.addCleanup(port_scanner.stop)
        from modules.scanner import NetworkScanner
        self.NetworkScanner = NetworkScanner
        self.scanner = NetworkScanner("127.0.0.1", 4)

    def test_initialization(self):
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.threads, 4)
        self.assertEqual(self.scanner.exclude_ports, [])

    @patch('os.geteuid', return_value=0)
    def test_scan_stealth_as_root(self, _):
        self.scanner.nm.scan.return_value = {'scan': {}}
        result = self.scanner.scan()
        self.scanner.nm.scan.assert_called_with("127.0.0.1", arguments="-sS -sV")
        self.assertEqual(result, {'scan': {}})

    @patch('os.geteuid', return_value=1000)
    def test_scan_connect_without_root(self, _):
        self.scanner.nm.scan.return_value = {'scan': {}}
        self.scanner.scan()
        self.scanner.nm.scan.assert_called_with("127.0.0.1", arguments="-sT -sV")

    @patch('os.geteuid', return_value=0)
    def test_scan_with_exclude_ports(self, _):
        scanner = self.NetworkScanner("10.0.0.1", 4, exclude_ports=[22, 80])
        scanner.nm.scan.return_value = {'scan': {}}
        scanner.scan()
        scanner.nm.scan.assert_called_with("10.0.0.1", arguments="-sS -sV --exclude-ports 22,80")

    @patch('os.geteuid', return_value=1000)
    def test_unprivileged_scan_with_excluded_ports_skips_host_discovery(self, _):
        # Unprivileged host discovery probes port 80; excluding it makes every host look down.
        scanner = self.NetworkScanner("10.0.0.1", 4, exclude_ports=[22, 80])
        scanner.nm.scan.return_value = {'scan': {}}
        scanner.scan()
        scanner.nm.scan.assert_called_with("10.0.0.1", arguments="-sT -sV -Pn --exclude-ports 22,80")


if __name__ == '__main__':
    unittest.main()

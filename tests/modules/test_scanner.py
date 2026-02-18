# test_scanner.py
import unittest
from unittest.mock import patch

class TestNetworkScanner(unittest.TestCase):
    def setUp(self):
        # Create a patcher for 'modules.scanner.nmap'
        self.nmap_patcher = patch('modules.scanner.nmap')
        self.mock_nmap = self.nmap_patcher.start()
        
        # Ensure the patcher is stopped after tests
        self.addCleanup(self.nmap_patcher.stop)
        
        # Import after patching
        from modules.scanner import NetworkScanner
        self.scanner = NetworkScanner("127.0.0.1", 4)

    def test_initialization(self):
        self.assertEqual(self.scanner.target, "127.0.0.1")
        self.assertEqual(self.scanner.threads, 4)

    def test_scan(self):
        # Mock the scan method
        self.scanner.nm.scan.return_value = {'scan': {}}
        
        result = self.scanner.scan()
        
        # Verify scan was called with correct arguments
        self.scanner.nm.scan.assert_called_with("127.0.0.1", arguments="-sS")
        self.assertEqual(result, {'scan': {}}) 
        # Wait, NetworkScanner.scan implementation:
        # future = executor.submit(self.nm.scan, ...)
        # scan_result = future.result()
        # self.nm.scan returns whatever mock returns.
        # But ThreadPoolExecutor runs it in a thread. 
        # Mock objects are pickleable? Usually yes for MagicMock.
        # But ThreadPoolExecutor might not like Mock objects if they are not pickleable across processes, but threads share memory.
        # Let's see if this simple test works.

if __name__ == '__main__':
    unittest.main()

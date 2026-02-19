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

    @patch('os.geteuid')
    def test_scan(self, mock_geteuid):
        # Force root privileges so scanner chooses -sS
        mock_geteuid.return_value = 0
        
        # Mock the scan method
        self.scanner.nm.scan.return_value = {'scan': {}}
        
        result = self.scanner.scan()
        
        # Verify scan was called with correct arguments
        # Since we mocked root, it should be -sS
        self.scanner.nm.scan.assert_called_with("127.0.0.1", arguments="-sS")
        self.assertEqual(result, {'scan': {}}) 

if __name__ == '__main__':
    unittest.main()

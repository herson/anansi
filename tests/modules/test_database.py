import unittest
from modules.database import ScanDatabase


class TestScanDatabase(unittest.TestCase):
    """All tests use an in-memory SQLite DB so no files are created on disk."""

    def setUp(self):
        self.db = ScanDatabase(':memory:')

    def test_create_scan_returns_id(self):
        scan_id = self.db.create_scan('192.168.1.1')
        self.assertIsInstance(scan_id, int)
        self.assertGreater(scan_id, 0)

    def test_new_scan_has_running_status(self):
        scan_id = self.db.create_scan('10.0.0.1')
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['status'], 'running')
        self.assertEqual(scan['target'], '10.0.0.1')
        self.assertIsNone(scan['completed_at'])

    def test_complete_scan_updates_status(self):
        scan_id = self.db.create_scan('10.0.0.1')
        results = {80: {'service': 'http', 'version': '2.4'}}
        self.db.complete_scan(scan_id, results)
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['status'], 'completed')
        self.assertIsNotNone(scan['completed_at'])
        self.assertIn('80', scan['results'])

    def test_fail_scan_updates_status(self):
        scan_id = self.db.create_scan('10.0.0.1')
        self.db.fail_scan(scan_id, RuntimeError("nmap not found"))
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['status'], 'failed')
        self.assertIn('error', scan['results'])

    def test_get_scan_returns_none_for_missing_id(self):
        result = self.db.get_scan(9999)
        self.assertIsNone(result)

    def test_list_scans_returns_most_recent_first(self):
        id1 = self.db.create_scan('10.0.0.1')
        id2 = self.db.create_scan('10.0.0.2')
        scans = self.db.list_scans()
        self.assertEqual(scans[0]['id'], id2)
        self.assertEqual(scans[1]['id'], id1)

    def test_list_scans_respects_limit(self):
        for i in range(5):
            self.db.create_scan(f'10.0.0.{i}')
        scans = self.db.list_scans(limit=3)
        self.assertEqual(len(scans), 3)

    def test_list_scans_excludes_results_blob(self):
        scan_id = self.db.create_scan('10.0.0.1')
        self.db.complete_scan(scan_id, {80: {'service': 'http'}})
        scans = self.db.list_scans()
        self.assertNotIn('results', scans[0])

    def test_multiple_scans_get_unique_ids(self):
        ids = [self.db.create_scan('10.0.0.1') for _ in range(3)]
        self.assertEqual(len(set(ids)), 3)


if __name__ == '__main__':
    unittest.main()

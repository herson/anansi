import json
import os
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from domain.changes import ScanOptions
from modules.database import ScanDatabase, Schedule

OPTIONS = ScanOptions('-sT -sV', cve_lookup=True, cve_lookup_complete=True)


class TestScanDatabase(unittest.TestCase):
    """All tests use an in-memory SQLite DB so no files are created on disk."""

    def setUp(self):
        self.db = ScanDatabase(':memory:')

    def test_uses_path_from_environment_when_none_given(self):
        with patch.dict(os.environ, {'ANANSI_DB_PATH': ':memory:'}):
            db = ScanDatabase()
        self.assertEqual(db.db_path, ':memory:')

    def test_explicit_path_overrides_environment(self):
        with patch.dict(os.environ, {'ANANSI_DB_PATH': 'elsewhere.db'}):
            db = ScanDatabase(':memory:')
        self.assertEqual(db.db_path, ':memory:')

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
        results = [{'host': '10.0.0.1', 'port': 80, 'service': 'http', 'cves': []}]
        self.db.complete_scan(scan_id, results, OPTIONS)
        scan = self.db.get_scan(scan_id)
        self.assertEqual(scan['status'], 'completed')
        self.assertIsNotNone(scan['completed_at'])
        self.assertEqual(json.loads(scan['results']), results)

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
        self.db.complete_scan(scan_id, [{'host': '10.0.0.1', 'port': 80}], OPTIONS)
        scans = self.db.list_scans()
        self.assertNotIn('results', scans[0])

    def test_multiple_scans_get_unique_ids(self):
        ids = [self.db.create_scan('10.0.0.1') for _ in range(3)]
        self.assertEqual(len(set(ids)), 3)


class TestScanOptions(unittest.TestCase):
    """How each scan ran, so it is compared only with scans that ran the same way (ADR-0013)."""

    def setUp(self):
        self.db = ScanDatabase(':memory:')

    def _completed(self, target='10.0.0.0/24', options=OPTIONS):
        scan_id = self.db.create_scan(target)
        self.db.complete_scan(scan_id, [], options)
        return scan_id

    def test_a_completed_scan_records_how_it_ran(self):
        scan = self.db.get_scan(self._completed())
        self.assertEqual(json.loads(scan['options']),
                         {'nmap_arguments': '-sT -sV', 'cve_lookup': True, 'cve_lookup_complete': True})

    def test_lists_earlier_completed_scans_newest_first(self):
        first, second = self._completed(), self._completed('10.0.0.5')
        current = self._completed()
        earlier = self.db.earlier_completed_scans(current)
        self.assertEqual([s['id'] for s in earlier], [second, first])
        self.assertEqual(set(earlier[0]), {'id', 'target', 'completed_at', 'options'})

    def test_running_failed_and_later_scans_are_not_listed(self):
        baseline = self._completed()
        running = self.db.create_scan('10.0.0.0/24')
        failed = self.db.create_scan('10.0.0.0/24')
        self.db.fail_scan(failed, RuntimeError('nmap not found'))
        current = self._completed()
        self._completed()
        self.assertEqual([s['id'] for s in self.db.earlier_completed_scans(current)], [baseline])
        self.assertNotIn(running, [s['id'] for s in self.db.earlier_completed_scans(current)])

    def test_adds_the_options_column_to_a_database_made_before_it_existed(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'anansi.db')
            with sqlite3.connect(path) as old:
                old.execute("""CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
                               started_at TEXT NOT NULL, completed_at TEXT,
                               status TEXT NOT NULL DEFAULT 'running', results TEXT)""")
                old.execute("""INSERT INTO scans (target, started_at, completed_at, status, results)
                               VALUES ('10.0.0.1', '2026-01-01', '2026-01-01', 'completed', '{}')""")
            old.close()
            db = ScanDatabase(path)
            self.assertIsNone(db.get_scan(1)['options'])
            current = db.create_scan('10.0.0.1')
            db.complete_scan(current, [], OPTIONS)
            self.assertEqual(db.earlier_completed_scans(current), [])
            ScanDatabase(path)  # opening it again leaves the column alone


class TestSchedules(unittest.TestCase):

    NIGHTLY = Schedule('scan-10.0.0.1-0_2_*_*_*', '10.0.0.1', '0 2 * * *', cve=False)

    def setUp(self):
        self.db = ScanDatabase(':memory:')

    def test_saved_schedules_are_listed(self):
        weekly = Schedule('scan-10.0.0.0/24-0_3_*_*_0', '10.0.0.0/24', '0 3 * * 0', cve=True)
        self.db.save_schedule(self.NIGHTLY)
        self.db.save_schedule(weekly)
        self.assertEqual(self.db.list_schedules(), [self.NIGHTLY, weekly])

    def test_saving_a_schedule_with_the_same_id_replaces_it(self):
        self.db.save_schedule(self.NIGHTLY)
        with_cve = Schedule(self.NIGHTLY.id, '10.0.0.1', '0 2 * * *', cve=True)
        self.db.save_schedule(with_cve)
        self.assertEqual(self.db.list_schedules(), [with_cve])

    def test_deleted_schedule_is_no_longer_listed(self):
        self.db.save_schedule(self.NIGHTLY)
        self.assertTrue(self.db.delete_schedule(self.NIGHTLY.id))
        self.assertEqual(self.db.list_schedules(), [])

    def test_deleting_an_unknown_schedule_reports_nothing_deleted(self):
        self.assertFalse(self.db.delete_schedule('scan-nope'))

    def test_schedules_survive_reopening_the_database_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'anansi.db')
            ScanDatabase(path).save_schedule(self.NIGHTLY)
            self.assertEqual(ScanDatabase(path).list_schedules(), [self.NIGHTLY])


if __name__ == '__main__':
    unittest.main()

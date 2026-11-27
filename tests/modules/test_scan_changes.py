import unittest

from domain.changes import ScanOptions
from domain.findings import Cve, Finding, findings_to_json
from modules.database import ScanDatabase
from modules.scan_changes import SERIES_LIMIT, changes_since_previous_scan, status_over_time

HTTP = Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49')
SSH = Finding('10.0.0.1', 22, 'tcp', 'ssh', 'OpenSSH', '8.2')
CVE = Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal')
CONNECT = ScanOptions('-sT -sV', cve_lookup=False, cve_lookup_complete=False)
WITH_CVES = ScanOptions('-sT -sV', cve_lookup=True, cve_lookup_complete=True)


class ScanChangesTestCase(unittest.TestCase):

    def setUp(self):
        self.db = ScanDatabase(':memory:')

    def scan(self, findings, target='10.0.0.0/24', options=CONNECT):
        scan_id = self.db.create_scan(target)
        self.db.complete_scan(scan_id, findings_to_json(findings), options)
        return scan_id


class TestBaseline(ScanChangesTestCase):

    def test_compares_with_the_previous_scan_of_the_same_network(self):
        baseline = self.scan([HTTP])
        self.scan([HTTP], target='10.0.1.0/24')
        current = self.scan([HTTP, SSH], target='10.0.0.7/24')
        answer = changes_since_previous_scan(self.db, current)
        self.assertTrue(answer['comparable'])
        self.assertEqual(answer['baseline']['id'], baseline)
        self.assertEqual([f['port'] for f in answer['changes']['opened']], [22])

    def test_skips_earlier_scans_that_ran_differently(self):
        baseline = self.scan([HTTP])
        self.scan([], options=ScanOptions('-sS -sV', False, False))
        self.scan([], options=WITH_CVES)
        current = self.scan([HTTP])
        self.assertEqual(changes_since_previous_scan(self.db, current)['baseline']['id'], baseline)

    def test_says_so_when_no_earlier_scan_ran_the_same_way(self):
        self.scan([HTTP], options=WITH_CVES)
        answer = changes_since_previous_scan(self.db, self.scan([HTTP]))
        self.assertFalse(answer['comparable'])
        self.assertIsNone(answer['baseline'])
        self.assertIsNone(answer['changes'])
        self.assertIn('No earlier scan', answer['reason'])

    def test_unknown_scan_gives_nothing(self):
        self.assertIsNone(changes_since_previous_scan(self.db, 99))


class TestScansThatCannotBeCompared(ScanChangesTestCase):

    def test_a_running_scan(self):
        answer = changes_since_previous_scan(self.db, self.db.create_scan('10.0.0.1'))
        self.assertFalse(answer['comparable'])
        self.assertIn("hasn't finished", answer['reason'])

    def test_a_failed_scan(self):
        scan_id = self.db.create_scan('10.0.0.1')
        self.db.fail_scan(scan_id, RuntimeError('nmap not found'))
        self.assertIn('failed', changes_since_previous_scan(self.db, scan_id)['reason'])

    def test_a_scan_saved_before_options_were_recorded(self):
        scan_id = self.db.create_scan('10.0.0.1')
        self.db._conn.execute("UPDATE scans SET status='completed', results='{}' WHERE id=?", (scan_id,))
        answer = changes_since_previous_scan(self.db, scan_id)
        self.assertFalse(answer['comparable'])
        self.assertIn('before Anansi recorded', answer['reason'])


class TestCves(ScanChangesTestCase):

    def test_cves_are_compared_when_both_lookups_completed(self):
        self.scan([HTTP], options=WITH_CVES)
        current = self.scan([Finding(HTTP.host, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', (CVE,))],
                            options=WITH_CVES)
        answer = changes_since_previous_scan(self.db, current)
        self.assertTrue(answer['cves_compared'])
        self.assertEqual([c['cves'][0]['id'] for c in answer['changes']['cves_added']], [CVE.id])

    def test_cves_are_not_compared_when_a_lookup_failed(self):
        self.scan([HTTP], options=ScanOptions('-sT -sV', cve_lookup=True, cve_lookup_complete=False))
        current = self.scan([Finding(HTTP.host, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', (CVE,))],
                            options=WITH_CVES)
        answer = changes_since_previous_scan(self.db, current)
        self.assertTrue(answer['comparable'])
        self.assertFalse(answer['cves_compared'])
        self.assertIn('lookup failed', answer['cves_reason'])
        self.assertEqual(answer['changes']['cves_added'], [])

    def test_cves_are_not_compared_when_neither_scan_looked_them_up(self):
        self.scan([HTTP])
        answer = changes_since_previous_scan(self.db, self.scan([HTTP]))
        self.assertFalse(answer['cves_compared'])
        self.assertIn("didn't look up CVEs", answer['cves_reason'])


class TestStatusOverTime(ScanChangesTestCase):

    def test_the_series_is_the_scan_and_earlier_comparable_scans_oldest_first(self):
        first = self.scan([HTTP])
        self.scan([HTTP], target='10.0.1.0/24')
        self.scan([], options=WITH_CVES)
        second = self.scan([HTTP, SSH])
        series = status_over_time(self.db, second)
        self.assertEqual([p.scan_id for p in series.points], [first, second])
        self.assertEqual([p.counts.open_ports for p in series.points], [1, 2])
        self.assertFalse(series.cve_lookup)

    def test_keeps_the_most_recent_scans_up_to_the_limit(self):
        ids = [self.scan([HTTP]) for _ in range(SERIES_LIMIT + 2)]
        series = status_over_time(self.db, ids[-1])
        self.assertEqual([p.scan_id for p in series.points], ids[-SERIES_LIMIT:])
        self.assertEqual(SERIES_LIMIT, 30)

    def test_cve_counts_are_missing_for_a_scan_whose_lookup_failed(self):
        self.scan([HTTP], options=WITH_CVES)
        self.scan([HTTP], options=ScanOptions('-sT -sV', cve_lookup=True, cve_lookup_complete=False))
        current = self.scan([Finding(HTTP.host, 80, 'tcp', 'http', 'Apache httpd', '2.4.49', (CVE,))],
                            options=WITH_CVES)
        series = status_over_time(self.db, current)
        self.assertTrue(series.cve_lookup)
        self.assertEqual([p.counts.cves and p.counts.cves['high'] for p in series.points], [0, None, 1])

    def test_no_series_with_fewer_than_two_scans(self):
        self.assertIsNone(status_over_time(self.db, self.scan([HTTP])))

    def test_no_series_for_a_scan_that_cannot_be_compared(self):
        self.scan([HTTP])
        running = self.db.create_scan('10.0.0.0/24')
        self.assertIsNone(status_over_time(self.db, running))
        self.assertIsNone(status_over_time(self.db, 99))


if __name__ == '__main__':
    unittest.main()

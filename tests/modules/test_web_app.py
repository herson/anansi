import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

# Stub nmap before any project module imports it
sys.modules.setdefault('nmap', MagicMock())
# The app's lifespan opens the database at ANANSI_DB_PATH; keep it off disk
os.environ.setdefault('ANANSI_DB_PATH', ':memory:')

MOCK_CONFIG = {
    'default': {
        'max_threads': 4,
        'exclude_ports': [],
        'report_format': 'json',
    }
}

from domain.changes import ScanOptions  # noqa: E402
from domain.findings import Cve, Finding, findings_to_json  # noqa: E402
from modules.database import Schedule  # noqa: E402

TEST_KEY = 'test-key-0123456789abcdef'
TWO_HOSTS = [
    Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49',
            (Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal'),)),
    Finding('10.0.0.2', 80, 'tcp', 'http', 'nginx', '1.18.0'),
]
HTML = {'Accept': 'text/html'}
OPTIONS = ScanOptions('-sT -sV', cve_lookup=False, cve_lookup_complete=False)


class WebAppTestCase(unittest.TestCase):
    """Fresh in-memory DB, idle state and a configured API key for every test."""

    def setUp(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        from fastapi.testclient import TestClient
        from modules.database import ScanDatabase
        from web.sessions import SessionStore
        import web.app as app_module

        app_module.db = ScanDatabase(':memory:')
        app_module.sessions = SessionStore()
        app_module.scheduler = BackgroundScheduler(daemon=True)
        with app_module._state_lock:
            app_module.IS_SCANNING = False
        app_module.SCAN_RESULTS = []
        app_module.app.state.api_key = TEST_KEY

        self.app_module = app_module
        self.client = TestClient(app_module.app, headers={'X-API-Key': TEST_KEY})
        self.anonymous = TestClient(app_module.app, follow_redirects=False)

    def login(self, client=None, key=TEST_KEY):
        client = client or self.anonymous
        return client.post('/login', data={'api_key': key})


class TestWebApp(WebAppTestCase):

    def test_status_returns_idle_state(self):
        resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["is_scanning"])
        self.assertFalse(data["results_available"])

    def test_scan_rejects_invalid_target(self):
        with patch('web.app.load_config', return_value=MOCK_CONFIG):
            resp = self.client.post("/scan?target=not_an_ip")
        self.assertEqual(resp.status_code, 400)

    def test_scan_accepts_valid_ip(self):
        with patch('web.app.run_scan_background'):
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                resp = self.client.post("/scan?target=192.168.1.1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")

    def test_scan_rejects_range_larger_than_limit(self):
        with patch('web.app.run_scan_background') as run:
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                resp = self.client.post("/scan?target=0.0.0.0/0")
        self.assertEqual(resp.status_code, 400)
        run.assert_not_called()

    def test_schedule_rejects_range_larger_than_limit(self):
        resp = self.client.post("/api/schedule?target=0.0.0.0/0&cron=0+2+*+*+*")
        self.assertEqual(resp.status_code, 400)

    def test_scan_accepts_cidr_range(self):
        with patch('web.app.run_scan_background'):
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                resp = self.client.post("/scan?target=10.0.0.0/24")
        self.assertEqual(resp.status_code, 200)

    def test_duplicate_scan_rejected(self):
        self.app_module.IS_SCANNING = True
        with patch('web.app.load_config', return_value=MOCK_CONFIG):
            resp = self.client.post("/scan?target=192.168.1.1")
        data = resp.json()
        self.assertEqual(data["status"], "error")
        self.assertIn("in progress", data["message"])

    def test_history_endpoint_returns_list(self):
        self.app_module.db.create_scan('10.0.0.1')
        self.app_module.db.create_scan('10.0.0.2')
        resp = self.client.get("/api/history")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()['scans']), 2)

    def test_get_scan_result_not_found(self):
        resp = self.client.get("/api/scan/9999")
        self.assertEqual(resp.status_code, 404)

    def test_get_scan_result_found(self):
        scan_id = self.app_module.db.create_scan('10.0.0.1')
        self.app_module.db.complete_scan(scan_id, findings_to_json(TWO_HOSTS), OPTIONS)
        resp = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'completed')
        self.assertEqual(resp.json()['results'], findings_to_json(TWO_HOSTS))
        self.assertEqual(resp.json()['options'],
                         {'nmap_arguments': '-sT -sV', 'cve_lookup': False, 'cve_lookup_complete': False})

    def test_schedule_rejects_invalid_target(self):
        resp = self.client.post("/api/schedule?target=bad&cron=0+2+*+*+*")
        self.assertEqual(resp.status_code, 400)

    def test_schedule_rejects_invalid_cron(self):
        resp = self.client.post("/api/schedule?target=10.0.0.1&cron=not-a-cron")
        self.assertEqual(resp.status_code, 400)

    def test_schedule_create_and_list(self):
        create = self.client.post("/api/schedule?target=10.0.0.1&cron=0+2+*+*+*")
        self.assertEqual(create.status_code, 200)
        job_id = create.json()['job_id']

        listing = self.client.get("/api/schedule")
        ids = [s['id'] for s in listing.json()['schedules']]
        self.assertIn(job_id, ids)

        delete = self.client.delete(f"/api/schedule/{job_id}")
        self.assertEqual(delete.status_code, 200)

        listing2 = self.client.get("/api/schedule")
        ids2 = [s['id'] for s in listing2.json()['schedules']]
        self.assertNotIn(job_id, ids2)


class TestSchedulesSurviveRestarts(WebAppTestCase):

    NIGHTLY = Schedule('scan-10.0.0.1-0_2_*_*_*', '10.0.0.1', '0 2 * * *', cve=True)

    def _job_ids(self):
        return [j.id for j in self.app_module.scheduler.get_jobs()]

    def test_created_schedule_is_saved_to_the_database(self):
        self.client.post("/api/schedule?target=10.0.0.1&cron=0+2+*+*+*&cve=true")
        self.assertEqual(self.app_module.db.list_schedules(), [self.NIGHTLY])

    def test_rejected_schedule_is_not_saved(self):
        self.client.post("/api/schedule?target=10.0.0.1&cron=not-a-cron")
        self.assertEqual(self.app_module.db.list_schedules(), [])

    def test_saved_schedules_are_scheduled_on_startup(self):
        self.app_module.db.save_schedule(self.NIGHTLY)
        self.app_module._restore_schedules()
        job = self.app_module.scheduler.get_job(self.NIGHTLY.id)
        self.assertIsNotNone(job)
        self.assertEqual(job.args, ('10.0.0.1', True))
        self.assertEqual(str(job.trigger), str(self.app_module.CronTrigger.from_crontab('0 2 * * *')))

    def test_invalid_saved_schedule_is_skipped_and_kept_for_inspection(self):
        tampered = Schedule('scan-x', '8.8.8.8; rm -rf /', '0 2 * * *', cve=False)
        bad_cron = Schedule('scan-y', '10.0.0.2', 'every night', cve=False)
        for schedule in (tampered, bad_cron, self.NIGHTLY):
            self.app_module.db.save_schedule(schedule)
        with self.assertLogs(level='WARNING') as logs:
            self.app_module._restore_schedules()
        self.assertEqual(self._job_ids(), [self.NIGHTLY.id])
        self.assertEqual(len(self.app_module.db.list_schedules()), 3)
        self.assertEqual(len(logs.output), 2)

    def test_deleting_a_schedule_removes_it_from_the_database(self):
        job_id = self.client.post("/api/schedule?target=10.0.0.1&cron=0+2+*+*+*").json()['job_id']
        self.assertEqual(self.client.delete(f"/api/schedule/{job_id}").status_code, 200)
        self.assertEqual(self.app_module.db.list_schedules(), [])
        self.assertEqual(self._job_ids(), [])

    def test_schedule_only_in_the_database_can_still_be_deleted(self):
        self.app_module.db.save_schedule(self.NIGHTLY)
        self.assertEqual(self.client.delete(f"/api/schedule/{self.NIGHTLY.id}").status_code, 200)
        self.assertEqual(self.app_module.db.list_schedules(), [])

    def test_unknown_schedule_is_not_found(self):
        self.assertEqual(self.client.delete("/api/schedule/scan-nope").status_code, 404)

    def test_schedule_is_listed_again_after_a_restart(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        from fastapi.testclient import TestClient
        from modules.database import ScanDatabase

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'anansi.db')
            self.app_module.db = ScanDatabase(path)
            job_id = self.client.post("/api/schedule?target=10.0.0.1&cron=0+2+*+*+*").json()['job_id']

            self.app_module.scheduler = BackgroundScheduler(daemon=True)
            with patch.dict(os.environ, {'ANANSI_DB_PATH': path}), \
                    TestClient(self.app_module.app, headers={'X-API-Key': TEST_KEY}) as restarted:
                listed = [s['id'] for s in restarted.get("/api/schedule").json()['schedules']]
        self.assertEqual(listed, [job_id])

    def test_the_scheduler_stops_when_the_app_shuts_down(self):
        from apscheduler.schedulers.background import BackgroundScheduler
        from fastapi.testclient import TestClient

        self.app_module.scheduler = BackgroundScheduler(daemon=True)
        with TestClient(self.app_module.app):
            self.assertTrue(self.app_module.scheduler.running)
        self.assertFalse(self.app_module.scheduler.running)


class TestScanPipeline(WebAppTestCase):

    def test_web_scans_never_run_exploitation(self):
        with patch('web.app.NetworkScanner') as scanner, \
                patch('web.app.ServiceEnumerator') as enumerator, \
                patch('modules.exploiter.Exploiter.exploit') as exploit:
            scanner.return_value.scan.return_value = {}
            scanner.return_value.arguments = '-sT -sV'
            enumerator.return_value.enumerate.return_value = TWO_HOSTS
            self.app_module.run_scan_background('10.0.0.0/24', 1, [])
        exploit.assert_not_called()
        self.assertEqual(self.app_module.SCAN_RESULTS, TWO_HOSTS)
        stored = self.client.get('/api/scan/1').json()['results']
        self.assertEqual(stored, findings_to_json(TWO_HOSTS))
        messages = [e['message'] for e in self.app_module.PROGRESS_EVENTS]
        self.assertFalse(any('xploit' in m for m in messages), messages)

    def test_the_dashboard_cannot_run_directory_discovery(self):
        source = (Path(self.app_module.__file__)).read_text()
        self.assertNotIn('dir_scan', source)
        self.assertNotIn('DirectoryScanner', source)

    def _run(self, cve=False, failed_lookups=0):
        with patch('web.app.NetworkScanner') as scanner, \
                patch('web.app.ServiceEnumerator') as enumerator, \
                patch('modules.vuln_lookup.VulnLookup') as lookup:
            scanner.return_value.scan.return_value = {}
            scanner.return_value.arguments = '-sT -sV'
            enumerator.return_value.enumerate.return_value = TWO_HOSTS
            lookup.return_value.enrich.return_value = TWO_HOSTS
            lookup.return_value.failed_lookups = failed_lookups
            self.app_module.run_scan_background('10.0.0.0/24', 1, [], cve)
        return self.client.get('/api/scan/1').json()['options']

    def test_a_completed_scan_records_how_it_ran(self):
        self.assertEqual(self._run(), {'nmap_arguments': '-sT -sV', 'cve_lookup': False,
                                       'cve_lookup_complete': False})

    def test_a_scan_whose_cve_lookups_all_answered_is_recorded_as_complete(self):
        self.assertEqual(self._run(cve=True), {'nmap_arguments': '-sT -sV', 'cve_lookup': True,
                                               'cve_lookup_complete': True})

    def test_a_failed_cve_lookup_is_recorded(self):
        self.assertFalse(self._run(cve=True, failed_lookups=2)['cve_lookup_complete'])


class TestScanChanges(WebAppTestCase):

    def _completed(self, findings):
        scan_id = self.app_module.db.create_scan('10.0.0.0/24')
        self.app_module.db.complete_scan(scan_id, findings_to_json(findings), OPTIONS)
        return scan_id

    def test_reports_changes_since_the_previous_comparable_scan(self):
        baseline = self._completed(TWO_HOSTS[:1])
        current = self._completed(TWO_HOSTS)
        answer = self.client.get(f'/api/scan/{current}/changes').json()
        self.assertEqual(answer['baseline']['id'], baseline)
        self.assertEqual([f['host'] for f in answer['changes']['opened']], ['10.0.0.2'])

    def test_unknown_scan_is_not_found(self):
        self.assertEqual(self.client.get('/api/scan/9999/changes').status_code, 404)

    def test_a_scan_id_that_is_not_a_number_is_rejected(self):
        self.assertEqual(self.client.get('/api/scan/abc/changes').status_code, 422)

    def test_the_dashboard_shows_changes_since_the_previous_scan(self):
        self._completed(TWO_HOSTS[:1])
        self._completed(TWO_HOSTS)
        html = self.client.get('/').text
        self.assertIn('Changes since', html)
        self.assertIn('Opened', html)
        self.assertIn('10.0.0.2', html)

    def test_the_dashboard_says_when_nothing_changed(self):
        self._completed(TWO_HOSTS)
        self._completed(TWO_HOSTS)
        html = self.client.get('/').text
        self.assertIn('Changes since', html)
        self.assertIn('No changes', html)

    def test_the_dashboard_shows_no_changes_panel_without_a_baseline(self):
        self._completed(TWO_HOSTS)
        self.assertNotIn('Changes since', self.client.get('/').text)


class TestStatusOverTime(WebAppTestCase):

    def _completed(self, findings, options=OPTIONS):
        scan_id = self.app_module.db.create_scan('10.0.0.0/24')
        self.app_module.db.complete_scan(scan_id, findings_to_json(findings), options)
        return scan_id

    def test_the_dashboard_charts_open_ports_across_comparable_scans(self):
        self._completed(TWO_HOSTS[:1])
        self._completed(TWO_HOSTS)
        html = self.client.get('/').text
        self.assertIn('id="chart-ports-title"', html)
        self.assertRegex(html, r'<svg[^>]*role="img"[^>]*aria-labelledby="chart-ports-title"'
                               r'[^>]*aria-describedby="chart-ports-table"')
        self.assertIn('<table class="table chart-table" id="chart-ports-table"', html)
        self.assertIn('<polyline', html)
        self.assertNotIn('id="chart-cves-title"', html)
        self.assertIn('look up CVEs', html)

    def test_the_cve_chart_shows_when_both_scans_looked_up_cves(self):
        with_cves = ScanOptions('-sT -sV', cve_lookup=True, cve_lookup_complete=True)
        self._completed(TWO_HOSTS[1:], with_cves)
        self._completed(TWO_HOSTS, with_cves)
        html = self.client.get('/').text
        self.assertIn('id="chart-cves-title"', html)
        self.assertIn('line--critical', html)
        self.assertIn('top 5 matches per service', html)

    def test_no_charts_with_a_single_scan(self):
        self._completed(TWO_HOSTS)
        self.assertNotIn('chart-ports', self.client.get('/').text)


class TestScanPage(WebAppTestCase):

    def _completed(self, findings, target='10.0.0.0/24'):
        scan_id = self.app_module.db.create_scan(target)
        self.app_module.db.complete_scan(scan_id, findings_to_json(findings), OPTIONS)
        return scan_id

    def test_shows_the_findings_stored_for_that_scan(self):
        first = self._completed(TWO_HOSTS[:1])
        self._completed(TWO_HOSTS[1:])
        html = self.client.get(f'/scans/{first}').text
        self.assertIn('Apache httpd', html)
        self.assertIn('CVE-2021-41773', html)
        self.assertNotIn('nginx', html)

    def test_says_how_the_scan_ran(self):
        html = self.client.get(f'/scans/{self._completed(TWO_HOSTS)}').text
        self.assertIn('10.0.0.0/24', html)
        self.assertIn('-sT -sV', html)
        self.assertIn('CVE lookup off', html)

    def test_compares_with_the_scan_before_it_not_the_latest(self):
        first = self._completed(TWO_HOSTS[:1])
        second = self._completed(TWO_HOSTS)
        self._completed(TWO_HOSTS[:1])
        html = self.client.get(f'/scans/{second}').text
        self.assertIn('Opened', html)
        self.assertIn(f'href="/scans/{first}"', html)

    def test_says_why_there_is_nothing_to_compare_with(self):
        html = self.client.get(f'/scans/{self._completed(TWO_HOSTS)}').text
        self.assertIn('No earlier scan of this target ran the same way.', html)

    def test_charts_status_up_to_that_scan(self):
        self._completed(TWO_HOSTS[:1])
        second = self._completed(TWO_HOSTS)
        later = self._completed(TWO_HOSTS)
        html = self.client.get(f'/scans/{second}').text
        self.assertIn('id="chart-ports-title"', html)
        self.assertIn('The last 2 scans', html)
        self.assertNotIn(f'href="/scans/{later}"', html)

    def test_a_failed_scan_shows_its_status_and_no_findings(self):
        scan_id = self.app_module.db.create_scan('10.0.0.1')
        self.app_module.db.fail_scan(scan_id, RuntimeError('nmap exploded'))
        resp = self.client.get(f'/scans/{scan_id}')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('failed', resp.text)
        self.assertIn('nmap exploded', resp.text)
        self.assertNotIn('<th scope="col">Port</th>', resp.text)

    def test_results_saved_in_the_old_format_are_explained_not_an_error(self):
        scan_id = self.app_module.db.create_scan('10.0.0.1')
        with self.app_module.db._conn:
            self.app_module.db._conn.execute(
                "UPDATE scans SET status='completed', results=? WHERE id=?",
                ('{"80": {"service": "http"}}', scan_id))
        resp = self.client.get(f'/scans/{scan_id}')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('older format', resp.text)

    def test_unknown_scan_is_not_found(self):
        self.assertEqual(self.client.get('/scans/9999').status_code, 404)

    def test_a_scan_id_that_is_not_a_number_is_rejected(self):
        self.assertEqual(self.client.get('/scans/abc').status_code, 422)

    def test_the_page_links_back_to_the_dashboard(self):
        html = self.client.get(f'/scans/{self._completed(TWO_HOSTS)}').text
        self.assertRegex(html, r'<a[^>]*href="/"')
        self.assertRegex(html, r'<h1[^>]*>[^<]*Scan #\d+')


class TestLinksToScans(WebAppTestCase):

    def _completed(self, findings):
        scan_id = self.app_module.db.create_scan('10.0.0.0/24')
        self.app_module.db.complete_scan(scan_id, findings_to_json(findings), OPTIONS)
        return scan_id

    def test_each_history_row_links_to_its_scan(self):
        first, second = self._completed(TWO_HOSTS), self._completed(TWO_HOSTS)
        history = self.client.get('/').text.split('id="history-heading"')[1]
        self.assertIn(f'<a href="/scans/{first}">', history)
        self.assertIn(f'<a href="/scans/{second}">', history)

    def test_the_chart_table_links_each_scan(self):
        first, second = self._completed(TWO_HOSTS[:1]), self._completed(TWO_HOSTS)
        table = self.client.get('/').text.split('id="chart-ports-table"')[1].split('</table>')[0]
        self.assertIn(f'<a href="/scans/{first}">', table)
        self.assertIn(f'<a href="/scans/{second}">', table)

    def test_chart_points_link_to_their_scan_for_pointer_users(self):
        first = self._completed(TWO_HOSTS[:1])
        self._completed(TWO_HOSTS)
        svg = self.client.get('/').text.split('<svg')[1].split('</svg>')[0]
        # The table's links serve keyboard and screen-reader users; the points stay out of the tab order.
        self.assertRegex(svg, rf'<a href="/scans/{first}" tabindex="-1">\s*<circle')


class TestScheduledScansShareTheScanSlot(WebAppTestCase):

    def _run_scheduled(self, on_scan=None):
        with patch('web.app.load_config', return_value=MOCK_CONFIG), \
                patch('web.app.NetworkScanner') as scanner, \
                patch('web.app.ServiceEnumerator') as enumerator:
            scanner.return_value.scan.side_effect = on_scan or (lambda: {})
            scanner.return_value.arguments = '-sT -sV'
            enumerator.return_value.enumerate.return_value = TWO_HOSTS
            self.app_module._run_scheduled_scan('10.0.0.0/24')
        return scanner

    def test_scheduled_scan_is_skipped_while_a_manual_scan_runs(self):
        self.app_module.IS_SCANNING = True
        self.app_module.PROGRESS_EVENTS = [{'message': 'manual scan progress', 'pct': 40}]
        with self.assertLogs(level='WARNING') as logs:
            scanner = self._run_scheduled()
        scanner.assert_not_called()
        self.assertTrue(self.app_module.IS_SCANNING)
        self.assertEqual(self.app_module.SCAN_RESULTS, [])
        self.assertEqual(self.app_module.PROGRESS_EVENTS, [{'message': 'manual scan progress', 'pct': 40}])
        self.assertIn('10.0.0.0/24', logs.output[0])

    def test_manual_scan_is_rejected_while_a_scheduled_scan_runs(self):
        responses = []

        def start_manual_scan_mid_way():
            with patch('web.app.run_scan_background') as manual:
                responses.append(self.client.post('/scan?target=10.0.0.9').json())
            responses.append(manual.called)
            return {}

        self._run_scheduled(on_scan=start_manual_scan_mid_way)
        self.assertEqual(responses[0]['status'], 'error')
        self.assertFalse(responses[1])
        self.assertFalse(self.app_module.IS_SCANNING)
        self.assertEqual(self.app_module.SCAN_RESULTS, TWO_HOSTS)

    def test_a_config_error_does_not_leave_the_slot_claimed(self):
        for error in (OSError('config.yaml missing'), None):
            load = {'side_effect': error} if error else {'return_value': {'default': {}}}
            with self.subTest(error=error), patch('web.app.load_config', **load):
                with self.assertRaises((OSError, KeyError)):
                    self.app_module._run_scheduled_scan('10.0.0.0/24')
                with self.assertRaises((OSError, KeyError)):
                    self.client.post('/scan?target=10.0.0.9')
                self.assertFalse(self.app_module.IS_SCANNING)


class TestDashboardRendersFindings(WebAppTestCase):

    def test_every_host_is_listed_even_when_they_share_a_port(self):
        self.app_module.SCAN_RESULTS = TWO_HOSTS
        html = self.client.get('/').text
        self.assertIn('<th scope="col">Host</th>', html)
        self.assertIn('10.0.0.1', html)
        self.assertIn('10.0.0.2', html)
        self.assertIn('Apache httpd', html)
        self.assertIn('nginx', html)
        self.assertIn('CVE-2021-41773', html)

    def test_findings_whose_cves_have_no_score_still_render(self):
        self.app_module.SCAN_RESULTS = [
            Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49',
                    (Cve('CVE-2099-0001', None, 'UNKNOWN', 'Awaiting analysis'),)),
        ]
        resp = self.client.get('/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('CVE-2099-0001', resp.text)


class TestEveryRouteRequiresCredentials(WebAppTestCase):

    PROTECTED = [
        ('GET', '/api/status'),
        ('GET', '/api/progress'),
        ('GET', '/api/history'),
        ('GET', '/api/scan/1'),
        ('GET', '/api/scan/1/changes'),
        ('GET', '/scans/1'),
        ('GET', '/api/schedule'),
        ('POST', '/api/schedule?target=10.0.0.1&cron=0+2+*+*+*'),
        ('DELETE', '/api/schedule/x'),
        ('POST', '/scan?target=10.0.0.1'),
        ('GET', '/docs'),
        ('GET', '/redoc'),
        ('GET', '/openapi.json'),
        ('GET', '/'),
    ]

    def test_requests_without_credentials_are_rejected(self):
        for method, path in self.PROTECTED:
            with self.subTest(method=method, path=path):
                resp = self.anonymous.request(method, path)
                self.assertEqual(resp.status_code, 401)

    def test_wrong_api_key_is_rejected(self):
        for method, path in self.PROTECTED:
            with self.subTest(method=method, path=path):
                resp = self.anonymous.request(method, path, headers={'X-API-Key': 'wrong'})
                self.assertEqual(resp.status_code, 401)

    def test_non_ascii_api_key_is_rejected_not_an_error(self):
        resp = self.anonymous.get('/api/status', headers={'X-API-Key': 'clé'.encode()})
        self.assertEqual(resp.status_code, 401)

    def test_cross_site_scan_request_without_credentials_starts_nothing(self):
        with patch('web.app.run_scan_background') as run:
            resp = self.anonymous.post('/scan?target=10.0.0.1',
                                       headers={'Origin': 'https://evil.example'})
        self.assertEqual(resp.status_code, 401)
        run.assert_not_called()

    def test_browser_without_session_is_redirected_to_login(self):
        resp = self.anonymous.get('/', headers=HTML)
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(resp.headers['location'], '/login')

    def test_everything_is_rejected_when_no_key_is_configured(self):
        self.app_module.app.state.api_key = None
        self.assertEqual(self.anonymous.get('/api/status').status_code, 401)
        self.assertEqual(self.login().status_code, 401)

    def test_login_page_and_static_files_are_public(self):
        self.assertEqual(self.anonymous.get('/login').status_code, 200)
        self.assertNotEqual(self.anonymous.get('/static/.gitkeep').status_code, 401)


class TestBrowserSessions(WebAppTestCase):

    def test_login_with_correct_key_sets_a_protected_session_cookie(self):
        resp = self.login()
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(resp.headers['location'], '/')
        cookie = resp.headers['set-cookie']
        self.assertIn('anansi_session=', cookie)
        self.assertIn('HttpOnly', cookie)
        self.assertIn('SameSite=strict', cookie)
        self.assertIn('Path=/', cookie)
        self.assertNotIn(TEST_KEY, cookie)

    def test_cookie_is_secure_only_over_https(self):
        self.assertNotIn('Secure', self.login().headers['set-cookie'])

        from fastapi.testclient import TestClient
        https = TestClient(self.app_module.app, base_url='https://testserver', follow_redirects=False)
        self.assertIn('Secure', self.login(https).headers['set-cookie'])

    def test_session_cookie_authenticates_pages_and_api(self):
        self.login()
        self.assertEqual(self.anonymous.get('/', headers=HTML).status_code, 200)
        self.assertEqual(self.anonymous.get('/api/status').status_code, 200)
        with patch('web.app.run_scan_background'), \
                patch('web.app.load_config', return_value=MOCK_CONFIG):
            self.assertEqual(self.anonymous.post('/scan?target=10.0.0.1').status_code, 200)

    def test_login_with_wrong_key_shows_an_accessible_error_and_no_cookie(self):
        resp = self.login(key='wrong-key')
        self.assertEqual(resp.status_code, 401)
        self.assertNotIn('set-cookie', resp.headers)
        self.assertIn('role="alert"', resp.text)

    def test_logout_ends_the_session(self):
        self.login()
        self.assertEqual(self.anonymous.get('/api/status').status_code, 200)
        resp = self.anonymous.post('/logout')
        self.assertEqual(resp.status_code, 303)
        self.assertEqual(resp.headers['location'], '/login')
        self.assertEqual(self.anonymous.get('/api/status').status_code, 401)

    def test_forged_session_cookie_is_rejected(self):
        self.anonymous.cookies.set('anansi_session', 'forged')
        self.assertEqual(self.anonymous.get('/api/status').status_code, 401)


class TestLoginPageAccessibility(WebAppTestCase):

    def test_key_field_is_labelled_password_input_submitted_by_a_native_form(self):
        html = self.anonymous.get('/login').text
        self.assertRegex(html, r'<form[^>]*method="post"[^>]*action="/login"')
        self.assertRegex(html, r'<label[^>]*for="api_key"')
        self.assertRegex(html, r'<input[^>]*id="api_key"[^>]*name="api_key"[^>]*type="password"')
        self.assertRegex(html, r'autocomplete="current-password"')
        self.assertRegex(html, r'<button[^>]*type="submit"')

    def test_error_is_linked_to_the_field(self):
        html = self.login(key='wrong-key').text
        self.assertRegex(html, r'aria-describedby="login-error"')
        self.assertRegex(html, r'id="login-error"[^>]*role="alert"')


class TestStartServer(unittest.TestCase):

    def setUp(self):
        import web.app as app_module
        self.app_module = app_module

    def _start(self, env):
        with patch.dict(os.environ, env, clear=True), patch('web.app.uvicorn.run') as run:
            self.app_module.start_server()
        return run

    def test_binds_to_loopback_by_default(self):
        run = self._start({})
        self.assertEqual(run.call_args.kwargs['host'], '127.0.0.1')

    def test_binds_to_configured_host_when_api_key_is_set(self):
        run = self._start({'ANANSI_HOST': '0.0.0.0', 'ANANSI_API_KEY': TEST_KEY})
        self.assertEqual(run.call_args.kwargs['host'], '0.0.0.0')
        self.assertEqual(self.app_module.app.state.api_key, TEST_KEY)

    def test_refuses_non_loopback_host_without_api_key(self):
        with self.assertRaises(SystemExit) as ctx:
            self._start({'ANANSI_HOST': '0.0.0.0'})
        self.assertIn('ANANSI_API_KEY', str(ctx.exception))

    def test_allows_localhost_name_without_api_key(self):
        run = self._start({'ANANSI_HOST': 'localhost'})
        self.assertEqual(run.call_args.kwargs['host'], 'localhost')

    def test_generates_and_prints_a_key_when_none_is_configured_on_loopback(self):
        with patch('builtins.print') as printed:
            self._start({})
        key = self.app_module.app.state.api_key
        self.assertGreaterEqual(len(key), 43)
        self.assertTrue(any(key in str(call) for call in printed.call_args_list))

    def test_generated_keys_differ_between_starts(self):
        with patch('builtins.print'):
            self._start({})
            first = self.app_module.app.state.api_key
            self._start({})
        self.assertNotEqual(first, self.app_module.app.state.api_key)

    def test_rejects_configured_key_shorter_than_16_characters(self):
        with self.assertRaises(SystemExit) as ctx:
            self._start({'ANANSI_API_KEY': 'short'})
        self.assertIn('16', str(ctx.exception))


if __name__ == '__main__':
    unittest.main()

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub nmap before any project module imports it
sys.modules.setdefault('nmap', MagicMock())
# web.app opens its database at import time; keep it off disk
os.environ.setdefault('ANANSI_DB_PATH', ':memory:')

MOCK_CONFIG = {
    'default': {
        'max_threads': 4,
        'exclude_ports': [],
        'metasploit_enabled': False,
        'report_format': 'json',
    }
}

TEST_KEY = 'test-key-0123456789abcdef'
HTML = {'Accept': 'text/html'}


class WebAppTestCase(unittest.TestCase):
    """Fresh in-memory DB, idle state and a configured API key for every test."""

    def setUp(self):
        from fastapi.testclient import TestClient
        from modules.database import ScanDatabase
        from web.sessions import SessionStore
        import web.app as app_module

        app_module.db = ScanDatabase(':memory:')
        app_module.sessions = SessionStore()
        with app_module._state_lock:
            app_module.IS_SCANNING = False
        app_module.SCAN_RESULTS = {}
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
        self.app_module.db.complete_scan(scan_id, {80: {'service': 'http'}})
        resp = self.client.get(f"/api/scan/{scan_id}")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['status'], 'completed')

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


class TestEveryRouteRequiresCredentials(WebAppTestCase):

    PROTECTED = [
        ('GET', '/api/status'),
        ('GET', '/api/progress'),
        ('GET', '/api/history'),
        ('GET', '/api/scan/1'),
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

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

# Stub nmap before any project module imports it
sys.modules.setdefault('nmap', MagicMock())

MOCK_CONFIG = {
    'default': {
        'max_threads': 4,
        'exclude_ports': [],
        'metasploit_enabled': False,
        'report_format': 'json',
    }
}


class TestWebApp(unittest.TestCase):

    def setUp(self):
        from fastapi.testclient import TestClient
        import web.app as app_module
        with app_module._state_lock:
            app_module.IS_SCANNING = False
        app_module.SCAN_RESULTS = {}
        self.client = TestClient(app_module.app)
        self.app_module = app_module

    def test_status_returns_idle_state(self):
        with patch.dict(os.environ, {}, clear=True):
            resp = self.client.get("/api/status")
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["is_scanning"])
        self.assertFalse(data["results_available"])

    def test_scan_rejects_invalid_target(self):
        with patch('web.app.load_config', return_value=MOCK_CONFIG):
            with patch.dict(os.environ, {}, clear=True):
                resp = self.client.post("/scan?target=not_an_ip")
        self.assertEqual(resp.status_code, 400)

    def test_scan_accepts_valid_ip(self):
        with patch('web.app.run_scan_background'):
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                with patch.dict(os.environ, {}, clear=True):
                    resp = self.client.post("/scan?target=192.168.1.1")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()["status"], "success")

    def test_scan_accepts_cidr_range(self):
        with patch('web.app.run_scan_background'):
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                with patch.dict(os.environ, {}, clear=True):
                    resp = self.client.post("/scan?target=10.0.0.0/24")
        self.assertEqual(resp.status_code, 200)

    def test_api_key_rejected_when_missing(self):
        with patch.dict(os.environ, {'ANANSI_API_KEY': 'secret'}):
            resp = self.client.post("/scan?target=192.168.1.1")
        self.assertEqual(resp.status_code, 403)

    def test_api_key_accepted_when_correct(self):
        with patch('web.app.run_scan_background'):
            with patch('web.app.load_config', return_value=MOCK_CONFIG):
                with patch.dict(os.environ, {'ANANSI_API_KEY': 'secret'}):
                    resp = self.client.post(
                        "/scan?target=192.168.1.1",
                        headers={"X-API-Key": "secret"},
                    )
        self.assertEqual(resp.status_code, 200)

    def test_duplicate_scan_rejected(self):
        self.app_module.IS_SCANNING = True
        with patch('web.app.load_config', return_value=MOCK_CONFIG):
            with patch.dict(os.environ, {}, clear=True):
                resp = self.client.post("/scan?target=192.168.1.1")
        data = resp.json()
        self.assertEqual(data["status"], "error")
        self.assertIn("in progress", data["message"])


if __name__ == '__main__':
    unittest.main()

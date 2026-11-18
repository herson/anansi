"""ADR-0002: the dashboard runs only code served by Anansi, under a strict CSP."""
import re
import unittest
from pathlib import Path

from tests.modules.test_web_app import TEST_KEY, WebAppTestCase

TEMPLATES = Path(__file__).resolve().parents[2] / "web" / "templates"
EXPECTED_CSP = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"


class TestContentSecurityPolicy(WebAppTestCase):

    def test_every_response_carries_the_strict_policy(self):
        responses = {
            'dashboard': self.client.get('/'),
            'login page': self.anonymous.get('/login'),
            'failed login': self.login(key='wrong-key'),
            'api': self.client.get('/api/status'),
            'unauthenticated api': self.anonymous.get('/api/status'),
            'static file': self.anonymous.get('/static/app.css'),
        }
        for name, resp in responses.items():
            with self.subTest(name):
                self.assertEqual(resp.headers.get('content-security-policy'), EXPECTED_CSP)

    def test_dashboard_assets_are_served_by_the_app(self):
        for path in ('/static/app.css', '/static/app.js'):
            with self.subTest(path):
                self.assertEqual(self.anonymous.get(path).status_code, 200)

    def test_third_party_docs_pages_are_gone_but_the_schema_remains(self):
        self.assertEqual(self.client.get('/docs').status_code, 404)
        self.assertEqual(self.client.get('/redoc').status_code, 404)
        schema = self.client.get('/openapi.json', headers={'X-API-Key': TEST_KEY})
        self.assertEqual(schema.status_code, 200)
        self.assertIn('/scan', schema.json()['paths'])


class TestTemplatesFollowThePolicy(unittest.TestCase):
    """The CSP would silently block these in the browser, so catch them here."""

    def _templates(self):
        files = sorted(TEMPLATES.glob("*.html"))
        self.assertTrue(files)
        return [(f.name, f.read_text()) for f in files]

    def test_no_inline_scripts(self):
        for name, html in self._templates():
            with self.subTest(name):
                for attrs, body in re.findall(r"<script([^>]*)>(.*?)</script>", html, re.S):
                    self.assertIn('src="/static/', attrs)
                    self.assertEqual(body.strip(), "")

    def test_no_inline_event_handlers_or_styles(self):
        for name, html in self._templates():
            with self.subTest(name):
                self.assertNotRegex(html, r"\son[a-z]+\s*=")
                self.assertNotRegex(html, r"\sstyle\s*=")
                self.assertNotRegex(html, r"<style[\s>]")

    def test_no_third_party_urls(self):
        for name, html in self._templates():
            with self.subTest(name):
                self.assertNotRegex(html, r"""(src|href)\s*=\s*["']?(https?:)?//""")


class TestDashboardScanFormAccessibility(WebAppTestCase):

    def setUp(self):
        super().setUp()
        self.html = self.client.get('/').text

    def test_target_field_has_a_visible_label(self):
        self.assertRegex(self.html, r'<label[^>]*for="targetInput"')
        self.assertRegex(self.html, r'<input[^>]*id="targetInput"')

    def test_scan_is_started_by_a_native_form_submit_so_enter_works(self):
        self.assertRegex(self.html, r'<form[^>]*id="scanForm"')
        self.assertRegex(self.html, r'<button[^>]*type="submit"[^>]*id="scanBtn"')

    def test_errors_are_announced_and_linked_to_the_field(self):
        self.assertRegex(self.html, r'aria-describedby="scanError"')
        self.assertRegex(self.html, r'id="scanError"[^>]*role="alert"')

    def test_progress_is_a_labelled_native_progress_element(self):
        self.assertRegex(self.html, r'<progress[^>]*id="progressBar"[^>]*aria-labelledby="progressMsg"')
        self.assertRegex(self.html, r'id="progressMsg"[^>]*aria-live="polite"')


if __name__ == "__main__":
    unittest.main()

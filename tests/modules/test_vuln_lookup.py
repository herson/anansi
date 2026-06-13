import unittest
from unittest.mock import patch, MagicMock
import requests
from modules.vuln_lookup import VulnLookup

_NVD_RESPONSE = {
    'totalResults': 1,
    'vulnerabilities': [{
        'cve': {
            'id': 'CVE-2021-41773',
            'descriptions': [{'lang': 'en', 'value': 'Path traversal in Apache HTTP Server.'}],
            'metrics': {
                'cvssMetricV31': [{'cvssData': {'baseScore': 7.5, 'baseSeverity': 'HIGH'}}]
            }
        }
    }]
}

_EMPTY_RESPONSE = {'totalResults': 0, 'vulnerabilities': []}


class TestVulnLookup(unittest.TestCase):

    def setUp(self):
        self.lookup = VulnLookup()

    def _mock_get(self, response_data):
        mock = MagicMock()
        mock.json.return_value = response_data
        mock.raise_for_status = MagicMock()
        return mock

    @patch('modules.vuln_lookup.requests.Session.get')
    def test_lookup_returns_cves(self, mock_get):
        mock_get.return_value = self._mock_get(_NVD_RESPONSE)
        result = self.lookup.lookup('apache', '2.4.49')
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['id'], 'CVE-2021-41773')
        self.assertEqual(result[0]['score'], 7.5)
        self.assertEqual(result[0]['severity'], 'HIGH')

    @patch('modules.vuln_lookup.requests.Session.get')
    def test_lookup_empty_results(self, mock_get):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        result = self.lookup.lookup('unknown-svc', '9.9.9')
        self.assertEqual(result, [])

    @patch('modules.vuln_lookup.requests.Session.get',
           side_effect=requests.RequestException("timeout"))
    def test_lookup_handles_network_error(self, _):
        result = self.lookup.lookup('apache', '2.4.49')
        self.assertEqual(result, [])

    def test_lookup_empty_query_skips_request(self):
        with patch('modules.vuln_lookup.requests.Session.get') as mock_get:
            result = self.lookup.lookup('', '')
            mock_get.assert_not_called()
        self.assertEqual(result, [])

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_adds_cves_key(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_NVD_RESPONSE)
        services = {
            80: {'service': 'http', 'version': '2.4.49'},
            443: {'service': 'https', 'version': '2.4.49'},
        }
        enriched = self.lookup.enrich(services)
        self.assertIn('cves', enriched[80])
        self.assertIn('cves', enriched[443])
        self.assertEqual(len(enriched[80]['cves']), 1)

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_sleeps_between_requests(self, mock_get, mock_sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        services = {80: {'service': 'http', 'version': ''}, 443: {'service': 'https', 'version': ''}}
        self.lookup.enrich(services)
        mock_sleep.assert_called_once()  # one sleep between two requests

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_preserves_existing_fields(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        services = {80: {'service': 'http', 'version': '1.0'}}
        enriched = self.lookup.enrich(services)
        self.assertEqual(enriched[80]['service'], 'http')
        self.assertEqual(enriched[80]['version'], '1.0')

    def test_api_key_sets_header(self):
        lookup = VulnLookup(api_key='test-key')
        self.assertEqual(lookup.session.headers.get('apiKey'), 'test-key')

    def test_api_key_shortens_delay(self):
        with_key = VulnLookup(api_key='key')
        without_key = VulnLookup()
        self.assertLess(with_key._delay, without_key._delay)

    def test_parse_cve_falls_back_cvss_versions(self):
        cve = {
            'id': 'CVE-2020-1234',
            'descriptions': [{'lang': 'en', 'value': 'Test vuln'}],
            'metrics': {
                'cvssMetricV30': [{'cvssData': {'baseScore': 5.0, 'baseSeverity': 'MEDIUM'}}]
            }
        }
        result = VulnLookup._parse_cve(cve)
        self.assertEqual(result['score'], 5.0)
        self.assertEqual(result['severity'], 'MEDIUM')

    def test_parse_cve_missing_metrics(self):
        cve = {
            'id': 'CVE-2020-0001',
            'descriptions': [{'lang': 'en', 'value': 'No score yet'}],
            'metrics': {}
        }
        result = VulnLookup._parse_cve(cve)
        self.assertIsNone(result['score'])
        self.assertEqual(result['severity'], 'UNKNOWN')


if __name__ == '__main__':
    unittest.main()

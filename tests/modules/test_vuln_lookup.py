import unittest
from unittest.mock import patch, MagicMock
import requests
from domain.findings import Cve, Finding
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

_CVE = Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal in Apache HTTP Server.')


def _finding(host='10.0.0.1', port=80, service='http', product='Apache httpd', version='2.4.49'):
    return Finding(host, port, 'tcp', service, product, version)


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
        self.assertEqual(result, [_CVE])

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

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_counts_failed_requests_so_an_empty_result_is_not_mistaken_for_no_cves(self, mock_get, _sleep):
        mock_get.side_effect = [requests.HTTPError("403 rate limited"), self._mock_get(_NVD_RESPONSE)]
        self.lookup.enrich([_finding(port=80), _finding(port=443)])
        self.assertEqual(self.lookup.failed_lookups, 1)

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_no_failed_requests_when_every_lookup_answers(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        self.lookup.enrich([_finding()])
        self.assertEqual(self.lookup.failed_lookups, 0)

    def test_lookup_empty_query_skips_request(self):
        with patch('modules.vuln_lookup.requests.Session.get') as mock_get:
            result = self.lookup.lookup('', '')
            mock_get.assert_not_called()
        self.assertEqual(result, [])

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_attaches_cves_to_each_finding(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_NVD_RESPONSE)
        findings = [_finding(port=80), _finding(host='10.0.0.2', port=80)]
        enriched = self.lookup.enrich(findings)
        self.assertEqual([f.cves for f in enriched], [(_CVE,), (_CVE,)])

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_keeps_every_other_field(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        original = _finding()
        self.assertEqual(self.lookup.enrich([original]), [original])

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_sleeps_between_requests(self, mock_get, mock_sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        self.lookup.enrich([_finding(port=80), _finding(port=443)])
        mock_sleep.assert_called_once()

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_searches_by_product_and_version(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        self.lookup.enrich([_finding(product='Apache httpd', version='2.4.49')])
        self.assertEqual(mock_get.call_args.kwargs['params']['keywordSearch'], 'Apache httpd 2.4.49')

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_falls_back_to_service_name_without_a_product(self, mock_get, _sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        self.lookup.enrich([_finding(service='ssh', product='', version='8.2')])
        self.assertEqual(mock_get.call_args.kwargs['params']['keywordSearch'], 'ssh 8.2')

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_skips_findings_without_a_detected_version(self, mock_get, mock_sleep):
        findings = [_finding(port=8000, product='', version=''), _finding(port=8001, product='', version='')]
        enriched = self.lookup.enrich(findings)
        mock_get.assert_not_called()
        mock_sleep.assert_not_called()
        self.assertEqual(enriched, findings)

    @patch('modules.vuln_lookup.time.sleep')
    @patch('modules.vuln_lookup.requests.Session.get')
    def test_enrich_sleeps_only_between_real_requests(self, mock_get, mock_sleep):
        mock_get.return_value = self._mock_get(_EMPTY_RESPONSE)
        self.lookup.enrich([
            _finding(port=1, version=''),
            _finding(port=2, version='1.0'),
            _finding(port=3, version=''),
            _finding(port=4, version='2.0'),
        ])
        self.assertEqual(mock_get.call_count, 2)
        mock_sleep.assert_called_once()

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
        self.assertEqual(result, Cve('CVE-2020-1234', 5.0, 'MEDIUM', 'Test vuln'))

    def test_parse_cve_missing_metrics(self):
        cve = {
            'id': 'CVE-2020-0001',
            'descriptions': [{'lang': 'en', 'value': 'No score yet'}],
            'metrics': {}
        }
        result = VulnLookup._parse_cve(cve)
        self.assertEqual(result, Cve('CVE-2020-0001', None, 'UNKNOWN', 'No score yet'))


if __name__ == '__main__':
    unittest.main()

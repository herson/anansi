import csv
import io
import json
import unittest
from unittest.mock import mock_open, patch

from domain.findings import Cve, Finding, findings_to_json
from modules.reporter import Reporter

FINDINGS = [
    Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49',
            (Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal'),
             Cve('CVE-2021-42013', 9.8, 'CRITICAL', 'RCE'))),
    Finding('10.0.0.2', 80, 'tcp', 'http', 'nginx', '1.18.0'),
]


class TestReporter(unittest.TestCase):

    def _generate(self, report_format, findings=FINDINGS):
        """Run the reporter with filesystem calls mocked; return (open mock, written text)."""
        opener = mock_open()
        with patch('builtins.open', opener), patch('os.makedirs'), patch('os.chmod') as chmod:
            Reporter(findings, report_format).generate_report()
        written = ''.join(call.args[0] for call in opener().write.call_args_list)
        return opener, chmod, written

    def test_json_report_is_the_list_of_findings(self):
        opener, chmod, written = self._generate('json')
        opener.assert_any_call('reports/report.json', 'w')
        chmod.assert_called_once_with('reports/report.json', 0o600)
        self.assertEqual(json.loads(written), findings_to_json(FINDINGS))

    def test_does_not_read_config_yaml(self):
        opener, _, _ = self._generate('json')
        self.assertNotIn('config.yaml', [c.args[0] for c in opener.call_args_list if c.args])

    def test_csv_report_has_one_row_per_host_and_port(self):
        opener, chmod, written = self._generate('csv')
        opener.assert_any_call('reports/report.csv', 'w', newline='')
        chmod.assert_called_once_with('reports/report.csv', 0o600)
        rows = list(csv.DictReader(io.StringIO(written)))
        self.assertEqual([(r['Host'], r['Port'], r['Protocol'], r['Product']) for r in rows], [
            ('10.0.0.1', '80', 'tcp', 'Apache httpd'),
            ('10.0.0.2', '80', 'tcp', 'nginx'),
        ])

    def test_csv_report_summarises_the_worst_cve(self):
        _, _, written = self._generate('csv')
        first, second = csv.DictReader(io.StringIO(written))
        self.assertEqual((first['CVE Count'], first['Top CVSS'], first['Top Severity']), ('2', '9.8', 'CRITICAL'))
        self.assertEqual((second['CVE Count'], second['Top CVSS'], second['Top Severity']), ('0', 'N/A', 'N/A'))


if __name__ == '__main__':
    unittest.main()

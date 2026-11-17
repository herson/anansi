import sys
import unittest
from unittest.mock import MagicMock

# Stub fpdf before any project import touches it
_fpdf_mock = MagicMock()
sys.modules['fpdf'] = _fpdf_mock

from domain.findings import Cve, Finding  # noqa: E402


class TestPDFReporter(unittest.TestCase):

    def setUp(self):
        # Give each test a fresh FPDF instance mock so call counts don't accumulate
        _fpdf_mock.FPDF.return_value = MagicMock()
        from modules.reporting_pdf import PDFReporter
        self.PDFReporter = PDFReporter

    def _make_reporter(self, metadata=None, results=None):
        return self.PDFReporter(metadata or {}, results or [])

    def _written_text(self, reporter):
        calls = [c for c in reporter.pdf.method_calls if c[0] in ('cell', 'multi_cell')]
        return ' '.join(str(c.args[2]) for c in calls if len(c.args) > 2)

    def test_generate_calls_pdf_output(self):
        reporter = self._make_reporter({'target': '10.0.0.1'}, [])
        reporter.generate('out.pdf')
        reporter.pdf.output.assert_called_once_with('out.pdf')

    def test_findings_are_grouped_under_each_host(self):
        findings = [
            Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4.49',
                    (Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal'),)),
            Finding('10.0.0.2', 80, 'tcp', 'http', 'nginx', '1.18.0'),
            Finding('10.0.0.1', 22, 'tcp', 'ssh', 'OpenSSH', '8.2'),
        ]
        reporter = self._make_reporter({'target': '10.0.0.0/24'}, findings)
        reporter.generate('out.pdf')
        text = self._written_text(reporter)
        self.assertEqual(text.count('Host 10.0.0.1'), 1)
        self.assertEqual(text.count('Host 10.0.0.2'), 1)
        self.assertLess(text.index('Host 10.0.0.1'), text.index('Port 22/tcp'))
        self.assertLess(text.index('Port 22/tcp'), text.index('Host 10.0.0.2'))
        self.assertIn('Apache httpd 2.4.49', text)
        self.assertIn('nginx 1.18.0', text)
        self.assertIn('CVE-2021-41773', text)

    def test_generate_with_empty_results(self):
        reporter = self._make_reporter({'target': '10.0.0.1'}, [])
        reporter.generate('out.pdf')
        self.assertIn('No open ports', self._written_text(reporter))

    def test_generate_uses_unknown_for_missing_target(self):
        reporter = self._make_reporter({}, [])
        reporter.generate('out.pdf')
        self.assertIn('Target: Unknown', self._written_text(reporter))

    def test_generate_default_filename(self):
        reporter = self._make_reporter()
        reporter.generate()
        reporter.pdf.output.assert_called_once_with('report.pdf')


if __name__ == '__main__':
    unittest.main()

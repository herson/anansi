import sys
import unittest
from unittest.mock import MagicMock

# Stub fpdf before any project import touches it
_fpdf_mock = MagicMock()
sys.modules['fpdf'] = _fpdf_mock


class TestPDFReporter(unittest.TestCase):

    def setUp(self):
        # Give each test a fresh FPDF instance mock so call counts don't accumulate
        _fpdf_mock.FPDF.return_value = MagicMock()
        from modules.reporting_pdf import PDFReporter
        self.PDFReporter = PDFReporter

    def _make_reporter(self, metadata=None, results=None):
        return self.PDFReporter(metadata or {}, results or {})

    def test_init_stores_metadata_and_results(self):
        reporter = self._make_reporter({'target': '10.0.0.1'}, {80: {'service': 'http', 'version': ''}})
        self.assertEqual(reporter.metadata['target'], '10.0.0.1')
        self.assertIn(80, reporter.results)

    def test_generate_calls_pdf_output(self):
        reporter = self._make_reporter({'target': '10.0.0.1'}, {})
        reporter.generate('out.pdf')
        reporter.pdf.output.assert_called_once_with('out.pdf')

    def test_generate_with_findings(self):
        results = {
            80: {'service': 'http', 'version': '2.4.49'},
            443: {'service': 'https', 'version': '2.4.49'},
        }
        reporter = self._make_reporter({'target': '10.0.0.1'}, results)
        reporter.generate('out.pdf')
        reporter.pdf.output.assert_called_once_with('out.pdf')

    def test_generate_with_empty_results(self):
        reporter = self._make_reporter({'target': '10.0.0.1'}, {})
        reporter.generate('out.pdf')
        reporter.pdf.output.assert_called_once_with('out.pdf')

    def test_generate_uses_unknown_for_missing_target(self):
        reporter = self._make_reporter({}, {})
        reporter.generate('out.pdf')
        reporter.pdf.output.assert_called_once_with('out.pdf')

    def test_generate_default_filename(self):
        reporter = self._make_reporter()
        reporter.generate()
        reporter.pdf.output.assert_called_once_with('report.pdf')


if __name__ == '__main__':
    unittest.main()

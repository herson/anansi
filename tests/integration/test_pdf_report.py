"""Renders with the real fpdf2: unit tests mock it, which is how C3 went unnoticed."""
import os
import tempfile
import unittest

from pypdf import PdfReader

from domain.findings import Cve, Finding
from modules.compliance import ComplianceMapper
from modules.reporting_pdf import PDFReporter, report_filename

FINDINGS = [
    Finding('10.0.0.5', 23, 'tcp', 'telnet', 'Linux telnetd', '0.17',
            (Cve('CVE-2020-10188', 9.8, 'CRITICAL', 'Remote code execution in telnetd'),)),
]


def _render(target, findings, compliance=None):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, report_filename(target))
        PDFReporter({'target': target}, findings).generate(path, compliance)
        return '\n'.join(page.extract_text() for page in PdfReader(path).pages)


class TestPdfReportWithRealFpdf(unittest.TestCase):

    def test_cidr_scan_report_contains_findings_and_compliance(self):
        text = _render('10.0.0.0/24', FINDINGS, ComplianceMapper(FINDINGS).map())
        self.assertIn('Host 10.0.0.5', text)
        self.assertIn('CVE-2020-10188', text)
        self.assertIn('Compliance Mapping', text)
        self.assertIn('10.0.0.5:23/tcp', text)

    def test_text_outside_latin1_is_rendered(self):
        banner = Finding('10.0.0.5', 80, 'tcp', 'http', 'Zażółć httpd', '2.0',
                         (Cve('CVE-2024-0001', 5.0, 'MEDIUM', 'Crafted “Host” header – crash'),))
        text = _render('10.0.0.5', [banner])
        self.assertIn('Zażółć httpd 2.0', text)
        self.assertIn('Crafted “Host” header – crash', text)


if __name__ == '__main__':
    unittest.main()

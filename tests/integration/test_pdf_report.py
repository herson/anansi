"""Renders with the real fpdf2: unit tests mock it, so they can't catch encoding failures."""
import os
import tempfile
import unittest

from pypdf import PdfReader

from domain.findings import Cve, Finding
from modules.reporting_pdf import PDFReporter


def _render(target, findings):
    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'report.pdf')
        PDFReporter({'target': target}, findings).generate(path)
        return '\n'.join(page.extract_text() for page in PdfReader(path).pages)


class TestPdfReportWithRealFpdf(unittest.TestCase):

    def test_text_outside_latin1_is_rendered(self):
        banner = Finding('10.0.0.5', 80, 'tcp', 'http', 'Zażółć httpd', '2.0',
                         (Cve('CVE-2024-0001', 5.0, 'MEDIUM', 'Crafted “Host” header – crash'),))
        text = _render('10.0.0.5', [banner])
        self.assertIn('Zażółć httpd 2.0', text)
        self.assertIn('Crafted “Host” header – crash', text)


if __name__ == '__main__':
    unittest.main()

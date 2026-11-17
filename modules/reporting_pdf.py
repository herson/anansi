import datetime
import re
from pathlib import Path

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from domain.findings import Finding

_SEVERITY_COLORS = {
    'CRITICAL': (220, 38, 38),
    'HIGH':     (234, 88, 12),
    'MEDIUM':   (202, 138, 4),
    'LOW':      (22, 163, 74),
}

# A Unicode TrueType font: fpdf2's built-in fonts are Latin-1 only, and CVE
# descriptions, service banners and control texts are not.
FONT = "DejaVu"
_FONT_DIR = Path(__file__).parent / "fonts"
_FONT_FILES = {"": "DejaVuSans.ttf", "B": "DejaVuSans-Bold.ttf", "I": "DejaVuSans-Oblique.ttf"}

ComplianceFindings = dict[str, list[dict[str, str]]]


def report_filename(target: str) -> str:
    """Name the report after the target, without the '/' of a CIDR or the ':' of IPv6."""
    return f"report_{re.sub(r'[^A-Za-z0-9.-]', '_', target)}.pdf"


class PDFReporter:
    def __init__(self, metadata: dict[str, str], findings: list[Finding]) -> None:
        """
        Args:
            metadata: Dict with scan metadata (e.g. {'target': '10.0.0.1'}).
            findings: Scan findings, grouped by host in the report.
        """
        self.metadata = metadata
        self.findings = findings
        self.pdf = FPDF()
        for style, file in _FONT_FILES.items():
            self.pdf.add_font(FONT, style, str(_FONT_DIR / file))
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.add_page()

    def generate(self, filename: str = "report.pdf",
                 compliance_findings: ComplianceFindings | None = None) -> None:
        """Render findings, and compliance findings if any, to a PDF file at the given path."""
        self.pdf.set_font(FONT, "B", 16)
        self._line(10, "Anansi Penetration Test Report", align="C")

        self.pdf.set_font(FONT, "I", 10)
        self._line(10, f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", align="C")
        self.pdf.ln(10)

        self.pdf.set_font(FONT, "B", 12)
        self._line(10, f"Target: {self.metadata.get('target', 'Unknown')}")
        self.pdf.ln(5)

        self.pdf.set_font(FONT, "B", 14)
        self._line(10, "Scan Findings")

        if not self.findings:
            self.pdf.set_font(FONT, "", 12)
            self._line(10, "No open ports or vulnerabilities found.")
        else:
            for host in dict.fromkeys(f.host for f in self.findings):
                self.pdf.set_font(FONT, "B", 13)
                self._line(10, f"Host {host}")
                for finding in self.findings:
                    if finding.host == host:
                        self._write_port_section(finding)

        if compliance_findings:
            self._write_compliance_section(compliance_findings)

        self.pdf.output(filename)
        print(f"PDF Report saved to {filename}")

    def _write_compliance_section(self, compliance_findings: ComplianceFindings) -> None:
        """Render the compliance mapping on a new page."""
        self.pdf.add_page()
        self.pdf.set_font(FONT, "B", 14)
        self._line(10, "Compliance Mapping")
        self.pdf.ln(3)

        if not compliance_findings:
            self.pdf.set_font(FONT, "", 12)
            self._line(10, "No compliance findings.")
            return

        for framework, findings in compliance_findings.items():
            self.pdf.set_font(FONT, "B", 12)
            self._line(8, framework)
            self.pdf.set_font(FONT, "", 10)

            if not findings:
                self._line(7, "  No triggered controls.")
            else:
                for item in findings:
                    self._paragraph(6, f"  • {item['control']}")
                    self.pdf.set_font(FONT, "I", 9)
                    self._paragraph(5, f"    Evidence: {item['evidence']}")
                    self.pdf.set_font(FONT, "", 10)
            self.pdf.ln(3)

    def _write_port_section(self, finding: Finding) -> None:
        """Render one port block including any associated CVEs."""
        self.pdf.set_font(FONT, "B", 12)
        self._line(10, f"Port {finding.port}/{finding.protocol} ({finding.service or 'unknown'})")

        self.pdf.set_font(FONT, "", 11)
        version = f"{finding.product} {finding.version}".strip() or "unknown"
        self._paragraph(8, f"Version: {version}")

        cves = finding.cves
        if cves:
            self.pdf.set_font(FONT, "I", 10)
            self._line(8, f"CVEs found: {len(cves)}")
            for cve in cves[:3]:
                severity = (cve.severity or 'UNKNOWN').upper()
                score = cve.score if cve.score is not None else 'N/A'
                self._paragraph(7, f"  [{cve.id}] CVSS {score} ({severity}): {cve.description[:150]}")
        self.pdf.ln(3)

    def _line(self, h: float, text: str, align: str = "") -> None:
        """Write one line of text and move to the start of the next."""
        self.pdf.cell(200, h, text, align=align, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def _paragraph(self, h: float, text: str) -> None:
        """Write wrapped text across the page and move below it."""
        self.pdf.multi_cell(0, h, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

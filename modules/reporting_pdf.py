from fpdf import FPDF
import datetime

_SEVERITY_COLORS = {
    'CRITICAL': (220, 38, 38),
    'HIGH':     (234, 88, 12),
    'MEDIUM':   (202, 138, 4),
    'LOW':      (22, 163, 74),
}


class PDFReporter:
    def __init__(self, metadata, results):
        """
        Args:
            metadata: Dict with scan metadata (e.g. {'target': '10.0.0.1'}).
            results: Dict of {port: {service, version, cves}} findings.
        """
        self.metadata = metadata
        self.results = results
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.add_page()

    def generate(self, filename="report.pdf"):
        """Render findings to a PDF file at the given path."""
        self.pdf.set_font("Arial", "B", 16)
        self.pdf.cell(200, 10, "Anansi Penetration Test Report", ln=True, align="C")

        self.pdf.set_font("Arial", "I", 10)
        self.pdf.cell(
            200, 10,
            f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            ln=True, align="C",
        )
        self.pdf.ln(10)

        self.pdf.set_font("Arial", "B", 12)
        self.pdf.cell(200, 10, f"Target: {self.metadata.get('target', 'Unknown')}", ln=True)
        self.pdf.ln(5)

        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(200, 10, "Scan Findings", ln=True)

        if not self.results:
            self.pdf.set_font("Arial", "", 12)
            self.pdf.cell(200, 10, "No open ports or vulnerabilities found.", ln=True)
        else:
            for port, info in self.results.items():
                self._write_port_section(port, info)

        self.pdf.output(filename)
        print(f"PDF Report saved to {filename}")

    def add_compliance_section(self, compliance_findings: dict):
        """Append a compliance mapping section to the PDF."""
        self.pdf.add_page()
        self.pdf.set_font("Arial", "B", 14)
        self.pdf.cell(200, 10, "Compliance Mapping", ln=True)
        self.pdf.ln(3)

        if not compliance_findings:
            self.pdf.set_font("Arial", "", 12)
            self.pdf.cell(200, 10, "No compliance findings.", ln=True)
            return

        for framework, findings in compliance_findings.items():
            self.pdf.set_font("Arial", "B", 12)
            self.pdf.cell(200, 8, framework, ln=True)
            self.pdf.set_font("Arial", "", 10)

            if not findings:
                self.pdf.cell(200, 7, "  No triggered controls.", ln=True)
            else:
                for item in findings:
                    self.pdf.multi_cell(0, 6, f"  • {item['control']}")
                    self.pdf.set_font("Arial", "I", 9)
                    self.pdf.multi_cell(0, 5, f"    Evidence: {item['evidence']}")
                    self.pdf.set_font("Arial", "", 10)
            self.pdf.ln(3)

    def _write_port_section(self, port, info):
        """Render one port block including any associated CVEs."""
        self.pdf.set_font("Arial", "B", 12)
        self.pdf.cell(200, 10, f"Port {port} ({info.get('service', 'unknown')})", ln=True)

        self.pdf.set_font("Arial", "", 11)
        self.pdf.multi_cell(0, 8, f"Version: {info.get('version', 'unknown')}")

        cves = info.get('cves', [])
        if cves:
            self.pdf.set_font("Arial", "I", 10)
            self.pdf.cell(200, 8, f"CVEs found: {len(cves)}", ln=True)
            for cve in cves[:3]:
                severity = (cve.get('severity') or 'UNKNOWN').upper()
                score = cve.get('score', 'N/A')
                desc = cve.get('description', '')[:150]
                self.pdf.multi_cell(
                    0, 7,
                    f"  [{cve['id']}] CVSS {score} ({severity}): {desc}",
                )
        self.pdf.ln(3)

from fpdf import FPDF
import datetime


class PDFReporter:
    def __init__(self, metadata, results):
        """
        Args:
            metadata: Dict with scan metadata (e.g. {'target': '10.0.0.1'}).
            results: Dict of {port: {service, version}} findings.
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
        self.pdf.set_font("Arial", "", 12)

        if not self.results:
            self.pdf.cell(200, 10, "No open ports or vulnerabilities found.", ln=True)
        else:
            for port, info in self.results.items():
                self.pdf.set_font("Arial", "B", 12)
                self.pdf.cell(200, 10, f"Port {port} ({info.get('service', 'unknown')})", ln=True)
                self.pdf.set_font("Arial", "", 11)
                self.pdf.multi_cell(0, 10, f"Version: {info.get('version', 'unknown')}")
                self.pdf.ln(2)

        self.pdf.output(filename)
        print(f"PDF Report saved to {filename}")

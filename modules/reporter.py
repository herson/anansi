import csv
import json
import os
import stat

import yaml

from domain.findings import Finding, findings_to_json

CSV_HEADER = ['Host', 'Port', 'Protocol', 'Service', 'Product', 'Version',
              'CVE Count', 'Top CVSS', 'Top Severity']


class Reporter:
    def __init__(self, findings: list[Finding]) -> None:
        self.findings = findings
        with open('config.yaml', 'r') as config_file:
            self.config = yaml.safe_load(config_file)
        self.report_format = self.config['default']['report_format']

    def generate_report(self) -> None:
        """Write the report in the format specified by config.yaml."""
        os.makedirs("reports", exist_ok=True)
        if self.report_format == "json":
            self._generate_json_report()
        elif self.report_format == "csv":
            self._generate_csv_report()

    def _generate_json_report(self) -> None:
        path = "reports/report.json"
        with open(path, "w") as file:
            json.dump(findings_to_json(self.findings), file, indent=2)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        print("JSON report generated.")

    def _generate_csv_report(self) -> None:
        path = "reports/report.csv"
        with open(path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(CSV_HEADER)
            for f in self.findings:
                scored = [c for c in f.cves if c.score is not None]
                top = max(scored, key=lambda c: c.score or 0.0, default=None)
                writer.writerow([
                    f.host, f.port, f.protocol, f.service, f.product, f.version,
                    len(f.cves),
                    top.score if top else 'N/A',
                    top.severity if top else 'N/A',
                ])
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        print("CSV report generated.")

import json
import csv
import os
import stat
import yaml


class Reporter:
    def __init__(self, results):
        """
        Args:
            results: Dict of {port: {service, version, cves}} scan findings.
        """
        self.results = results
        with open('config.yaml', 'r') as config_file:
            self.config = yaml.safe_load(config_file)
        self.report_format = self.config['default']['report_format']

    def generate_report(self):
        """Write the report in the format specified by config.yaml."""
        os.makedirs("reports", exist_ok=True)
        if self.report_format == "json":
            self._generate_json_report()
        elif self.report_format == "csv":
            self._generate_csv_report()

    def _generate_json_report(self):
        path = "reports/report.json"
        with open(path, "w") as file:
            json.dump(self.results, file, indent=2)
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        print("JSON report generated.")

    def _generate_csv_report(self):
        path = "reports/report.csv"
        with open(path, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(['Port', 'Service', 'Version', 'CVE Count', 'Top CVSS', 'Top Severity'])
            for port, info in self.results.items():
                if not isinstance(info, dict):
                    writer.writerow([port, info, '', 0, 'N/A', 'N/A'])
                    continue
                cves = info.get('cves', [])
                scored = [c for c in cves if c.get('score') is not None]
                top = max(scored, key=lambda c: c['score'], default=None)
                writer.writerow([
                    port,
                    info.get('service', ''),
                    info.get('version', ''),
                    len(cves),
                    top['score'] if top else 'N/A',
                    top['severity'] if top else 'N/A',
                ])
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
        print("CSV report generated.")

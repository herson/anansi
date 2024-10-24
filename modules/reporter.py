import json
import csv
import yaml

class Reporter:
    def __init__(self, results):
        self.results = results
        with open('config.yaml', 'r') as file:  # Load the config from YAML
            config = yaml.safe_load(file)  # Load the YAML configuration
        self.report_format = config['default']['report_format']

    def generate_report(self):
        if self.report_format == "json":
            self._generate_json_report()
        elif self.report_format == "csv":
            self._generate_csv_report()

    def _generate_json_report(self):
        with open("reports/report.json", "w") as file:
            json.dump(self.results, file)
        print("JSON report generated.")

    def _generate_csv_report(self):
        with open("reports/report.csv", "w", newline="") as file:
            writer = csv.writer(file)
            for key, value in self.results.items():
                writer.writerow([key, value])
        print("CSV report generated.")

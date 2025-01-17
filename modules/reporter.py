import json
import csv
import yaml

class Reporter:
    def __init__(self, results):
        self.results = results
        with open('config.yaml', 'r') as config_file:
            self.config = yaml.safe_load(config_file)  # Load the config
        self.report_format = self.config['default']['report_format']  # Access the report format

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

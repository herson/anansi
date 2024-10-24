import unittest
from unittest.mock import patch, mock_open
import json
import csv
from modules.reporter import Reporter

class TestReporter(unittest.TestCase):

    @patch('builtins.open', new_callable=mock_open, read_data='default:\n  report_format: json')
    def test_init_json(self, mock_file):
        reporter = Reporter(results={})
        self.assertEqual(reporter.report_format, 'json')
        mock_file.assert_called_once_with('config.yaml', 'r')

    @patch('builtins.open', new_callable=mock_open, read_data='default:\n  report_format: csv')
    def test_init_csv(self, mock_file):
        reporter = Reporter(results={})
        self.assertEqual(reporter.report_format, 'csv')
        mock_file.assert_called_once_with('config.yaml', 'r')

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_generate_json_report(self, mock_json_dump, mock_file):
        reporter = Reporter(results={'key1': 'value1'})
        reporter.generate_report()
        mock_file.assert_called_once_with("reports/report.json", "w")
        mock_json_dump.assert_called_once_with({'key1': 'value1'}, mock_file())

    @patch('builtins.open', new_callable=mock_open)
    @patch('csv.writer')
    def test_generate_csv_report(self, mock_csv_writer, mock_file):
        reporter = Reporter(results={'key1': 'value1', 'key2': 'value2'})
        reporter.report_format = 'csv'  # Set report format to CSV
        reporter.generate_report()
        mock_file.assert_called_once_with("reports/report.csv", "w", newline="")
        mock_csv_writer().writerow.assert_any_call(['key1', 'value1'])
        mock_csv_writer().writerow.assert_any_call(['key2', 'value2'])

if __name__ == '__main__':
    unittest.main()

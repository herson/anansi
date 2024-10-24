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

    @patch('builtins.open', new_callable=mock_open, read_data='default:\n  report_format: json')
    def test_generate_json_report(self, mock_file):
        reporter = Reporter(results={'key1': 'value1'})
        reporter.generate_report()
        
        # Check if the report format is set correctly
        self.assertEqual(reporter.report_format, 'json')
        
        # Assert that open was called twice: once for config and once for report
        self.assertEqual(mock_file.call_count, 2)
        mock_file.assert_any_call("reports/report.json", "w")  # Check for report file
        mock_file.assert_any_call("config.yaml", "r")  # Check for config file

    @patch('builtins.open', new_callable=mock_open, read_data='default:\n  report_format: csv')
    def test_generate_csv_report(self, mock_file):
        reporter = Reporter(results={'key1': 'value1', 'key2': 'value2'})
        reporter.generate_report()
        
        # Check if the report format is set correctly
        self.assertEqual(reporter.report_format, 'csv')
        
        # Assert that open was called twice: once for config and once for report
        self.assertEqual(mock_file.call_count, 2)
        mock_file.assert_any_call("reports/report.csv", "w", newline="")  # Check for report file
        mock_file.assert_any_call("config.yaml", "r")  # Check for config file

if __name__ == '__main__':
    unittest.main()

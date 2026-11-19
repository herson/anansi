import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

sys.modules.setdefault('nmap', MagicMock())

import main  # noqa: E402
from domain.findings import Cve, Finding  # noqa: E402
from modules.cloud import BucketReport  # noqa: E402
from modules.config import ConfigError  # noqa: E402
from modules.dir_scan import DirectoryReport  # noqa: E402
from domain.findings import PathFinding  # noqa: E402

_logging = patch('main.configure_logging')


def setUpModule():
    _logging.start()


def tearDownModule():
    _logging.stop()


SERVICES = [Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4')]


class TestExploitationIsOptIn(unittest.TestCase):

    def _run(self, *args):
        argv = ['main.py', '--target', '10.0.0.1', *args]
        with patch.object(sys, 'argv', argv), \
                patch('main.NetworkScanner') as scanner, \
                patch('main.ServiceEnumerator') as enumerator, \
                patch('main.Exploiter') as exploiter, \
                patch('main.Reporter') as reporter:
            scanner.return_value.scan.return_value = {}
            enumerator.return_value.enumerate.return_value = SERVICES
            exploiter.return_value.exploit.return_value = SERVICES
            main.main()
        return exploiter, reporter

    def test_scan_does_not_run_exploitation_by_default(self):
        exploiter, reporter = self._run()
        exploiter.assert_not_called()
        reporter.assert_called_once_with(SERVICES, 'json')

    def test_exploit_flag_runs_exploitation(self):
        exploiter, reporter = self._run('--exploit')
        exploiter.assert_called_once_with(SERVICES)
        reporter.assert_called_once_with(SERVICES, 'json')


class TestStartup(unittest.TestCase):

    def test_config_error_is_printed_and_exits_non_zero(self):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', '--target', '10.0.0.1']), \
                patch('main.load_config', side_effect=ConfigError('config.yaml not found')), \
                patch('main.NetworkScanner') as scanner, redirect_stdout(out), \
                self.assertRaises(SystemExit) as exit:
            main.main()
        self.assertEqual(exit.exception.code, 1)
        self.assertIn('config.yaml not found', out.getvalue())
        scanner.assert_not_called()

    def test_unknown_report_format_stops_before_the_scan(self):
        out = io.StringIO()
        config = {'default': {'max_threads': 10, 'report_format': 'xml'}}
        with patch.object(sys, 'argv', ['main.py', '--target', '10.0.0.1']), \
                patch('main.load_config', return_value=config), \
                patch('main.NetworkScanner') as scanner, redirect_stdout(out), \
                self.assertRaises(SystemExit) as exit:
            main.main()
        self.assertEqual(exit.exception.code, 1)
        self.assertIn("'xml'", out.getvalue())
        scanner.assert_not_called()

    def test_logging_is_configured_when_the_cli_runs(self):
        with patch.object(sys, 'argv', ['main.py', '--s3', 'my-bucket']), \
                patch('modules.cloud.CloudScanner') as scanner, redirect_stdout(io.StringIO()):
            scanner.return_value.scan_bucket.return_value = BucketReport('my-bucket')
            main.configure_logging.reset_mock()
            main.main()
        main.configure_logging.assert_called_once_with()


class TestAiAnalysis(unittest.TestCase):

    def test_ai_analyses_the_findings_after_the_cve_lookup(self):
        enriched = [Finding('10.0.0.1', 80, 'tcp', 'http', 'Apache httpd', '2.4',
                            (Cve('CVE-2021-41773', 7.5, 'HIGH', 'Path traversal'),))]
        argv = ['main.py', '--target', '10.0.0.1', '--cve', '--ai']
        with patch.object(sys, 'argv', argv), \
                patch('main.NetworkScanner') as scanner, \
                patch('main.ServiceEnumerator') as enumerator, \
                patch('modules.vuln_lookup.VulnLookup') as lookup, \
                patch('main.IntelligentAnalyzer') as analyzer, \
                patch('main.Reporter'), redirect_stdout(io.StringIO()):
            scanner.return_value.scan.return_value = {}
            enumerator.return_value.enumerate.return_value = SERVICES
            lookup.return_value.enrich.return_value = enriched
            analyzer.return_value.analyze.return_value = 'ok'
            main.main()
        analyzer.return_value.analyze.assert_called_once_with(enriched)

    def test_invalid_ai_settings_stop_before_the_scan(self):
        argv = ['main.py', '--target', '10.0.0.1', '--ai']
        out = io.StringIO()
        with patch.object(sys, 'argv', argv), \
                patch('main.NetworkScanner') as scanner, \
                patch('main.IntelligentAnalyzer', side_effect=ValueError('ai_token_parameter must be ...')), \
                redirect_stdout(out), self.assertRaises(SystemExit) as exit:
            main.main()
        self.assertEqual(exit.exception.code, 1)
        self.assertIn('ai_token_parameter', out.getvalue())
        scanner.assert_not_called()


class TestS3Scan(unittest.TestCase):

    def _run(self, report):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', '--s3', 'my-bucket']), \
                patch('modules.cloud.CloudScanner') as scanner, redirect_stdout(out):
            scanner.return_value.scan_bucket.return_value = report
            try:
                main.main()
                code = 0
            except SystemExit as exit:
                code = exit.code
        return code, json.loads(out.getvalue().split('\n', 1)[1])

    def test_bucket_with_issues_prints_them_and_exits_zero(self):
        code, printed = self._run(BucketReport('my-bucket', ['Bucket policy makes the bucket public'], []))
        self.assertEqual(code, 0)
        self.assertEqual(printed, {'bucket': 'my-bucket', 'issues': ['Bucket policy makes the bucket public'],
                                   'errors': []})

    def test_incomplete_scan_exits_non_zero(self):
        code, printed = self._run(BucketReport('my-bucket', [], ['AWS credentials not found']))
        self.assertEqual(code, 1)
        self.assertEqual(printed['errors'], ['AWS credentials not found'])

    def test_invalid_bucket_name_stops_before_the_scan(self):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', '--s3', 'Not_A_Bucket']), \
                patch('modules.cloud.CloudScanner') as scanner, redirect_stdout(out), \
                self.assertRaises(SystemExit) as exit:
            main.main()
        self.assertEqual(exit.exception.code, 1)
        self.assertIn("'Not_A_Bucket' is not a valid S3 bucket name", out.getvalue())
        scanner.assert_not_called()


class TestInvalidInputStopsBeforeTheScan(unittest.TestCase):

    def _run(self, *args):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', *args]), \
                patch('main.NetworkScanner') as scanner, redirect_stdout(out), \
                self.assertRaises(SystemExit) as exit:
            main.main()
        scanner.assert_not_called()
        self.assertEqual(exit.exception.code, 1)
        return out.getvalue()

    def test_thread_count_outside_1_to_100(self):
        for threads in ('0', '101'):
            with self.subTest(threads=threads):
                self.assertIn('--threads must be between 1 and 100',
                              self._run('--target', '10.0.0.1', '--threads', threads))

    def test_missing_target(self):
        self.assertIn('--target is required', self._run())

    def test_target_that_is_not_an_address_or_range(self):
        self.assertIn("'example.com' must be an IP address or a CIDR range",
                      self._run('--target', 'example.com'))


class TestOtherModes(unittest.TestCase):

    def test_dns_prints_the_enumeration_without_scanning(self):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', '--dns', 'example.com']), \
                patch('modules.dns_enum.DNSEnumerator') as dns, \
                patch('main.NetworkScanner') as scanner, redirect_stdout(out):
            dns.return_value.enumerate.return_value = {'domain': 'example.com'}
            main.main()
        dns.assert_called_once_with('example.com')
        self.assertIn('"domain": "example.com"', out.getvalue())
        scanner.assert_not_called()

    def test_dns_prints_non_ascii_names_as_characters(self):
        out = io.StringIO()
        with patch.object(sys, 'argv', ['main.py', '--dns', 'example.com']), \
                patch('modules.dns_enum.DNSEnumerator') as dns, redirect_stdout(out):
            dns.return_value.enumerate.return_value = {'records': {'TXT': ['café – §']}}
            main.main()
        self.assertIn('café – §', out.getvalue())

    def test_web_starts_the_dashboard_without_scanning(self):
        with patch.object(sys, 'argv', ['main.py', '--web']), \
                patch('web.app.start_server') as start_server, \
                patch('main.NetworkScanner') as scanner:
            main.main()
        start_server.assert_called_once_with()
        scanner.assert_not_called()


class TestReportsAfterTheScan(unittest.TestCase):

    def _run(self, *args):
        argv = ['main.py', '--target', '10.0.0.1', *args]
        with patch.object(sys, 'argv', argv), \
                patch('main.NetworkScanner') as scanner, \
                patch('main.ServiceEnumerator') as enumerator, \
                patch('main.Reporter'), \
                patch('modules.compliance.ComplianceMapper') as mapper, \
                patch('modules.reporting_pdf.PDFReporter') as pdf, \
                redirect_stdout(io.StringIO()):
            scanner.return_value.scan.return_value = {}
            enumerator.return_value.enumerate.return_value = SERVICES
            mapper.return_value.map.return_value = {'PCI-DSS': []}
            main.main()
        return mapper, pdf

    def test_compliance_without_values_checks_every_framework(self):
        mapper, _ = self._run('--compliance')
        mapper.assert_called_once_with(SERVICES)
        mapper.return_value.map.assert_called_once_with(frameworks=None)

    def test_compliance_prints_dashes_and_section_signs_as_characters(self):
        argv = ['main.py', '--target', '10.0.0.1', '--compliance', 'HIPAA']
        out = io.StringIO()
        with patch.object(sys, 'argv', argv), \
                patch('main.NetworkScanner') as scanner, \
                patch('main.ServiceEnumerator') as enumerator, \
                patch('main.Reporter'), redirect_stdout(out):
            scanner.return_value.scan.return_value = {}
            enumerator.return_value.enumerate.return_value = SERVICES
            main.main()
        self.assertIn('HIPAA § 164.312(e)(1) –', out.getvalue())
        self.assertNotIn('\\u', out.getvalue())

    def test_compliance_with_values_checks_only_those_frameworks(self):
        mapper, _ = self._run('--compliance', 'HIPAA')
        mapper.return_value.map.assert_called_once_with(frameworks=['HIPAA'])

    def test_no_compliance_mapping_without_the_flag(self):
        mapper, _ = self._run()
        mapper.assert_not_called()

    def test_pdf_includes_the_compliance_mapping(self):
        _, pdf = self._run('--compliance', '--pdf')
        pdf.assert_called_once_with({'target': '10.0.0.1'}, SERVICES)
        pdf.return_value.generate.assert_called_once_with('report_10.0.0.1.pdf', {'PCI-DSS': []})

    def test_pdf_without_compliance_has_an_empty_mapping(self):
        _, pdf = self._run('--pdf')
        pdf.return_value.generate.assert_called_once_with('report_10.0.0.1.pdf', {})


class TestDirectoryDiscovery(unittest.TestCase):

    def _run(self, *args, report=None, config=None):
        out = io.StringIO()
        report = report or DirectoryReport('http://10.0.0.1/', [PathFinding('http://10.0.0.1/admin/', 200, 14)], [])
        with patch.object(sys, 'argv', ['main.py', *args]), \
                patch('modules.dir_scan.DirectoryScanner') as scanner, \
                patch('main.NetworkScanner') as network, redirect_stdout(out):
            if config is not None:
                load = patch('main.load_config', return_value=config)
                load.start()
                self.addCleanup(load.stop)
            scanner.return_value.scan.return_value = report
            try:
                main.main()
                code = 0
            except SystemExit as exit:
                code = exit.code
        network.assert_not_called()
        return code, out.getvalue(), scanner

    def test_prints_the_paths_found_as_json(self):
        code, out, scanner = self._run('--dirs', 'http://10.0.0.1/')
        self.assertEqual(code, 0)
        printed = json.loads(out[out.index('{'):])
        self.assertEqual(printed['found'], [{'url': 'http://10.0.0.1/admin/', 'status': 200, 'length': 14,
                                             'location': ''}])
        scanner.assert_called_once_with('http://10.0.0.1/', None, rate=10, verify_tls=True)

    def test_uses_the_rate_and_tls_settings_from_config(self):
        config = {'default': {'max_threads': 10, 'report_format': 'json', 'dirs_rate': 2,
                              'dirs_verify_tls': False}}
        _, _, scanner = self._run('--dirs', 'https://intranet/', config=config)
        scanner.assert_called_once_with('https://intranet/', None, rate=2, verify_tls=False)

    def test_reads_the_wordlist_file_given(self):
        with tempfile.NamedTemporaryFile('w', suffix='.txt', delete=False) as wordlist:
            wordlist.write('admin/\n\n# comment\nbackup.zip\n')
        self.addCleanup(os.unlink, wordlist.name)
        _, _, scanner = self._run('--dirs', 'http://10.0.0.1/', '--wordlist', wordlist.name)
        self.assertEqual(scanner.call_args.args[1], ['admin/', '', '# comment', 'backup.zip'])

    def test_a_missing_wordlist_file_stops_before_any_request(self):
        code, out, scanner = self._run('--dirs', 'http://10.0.0.1/', '--wordlist', '/nonexistent/words.txt')
        self.assertEqual(code, 1)
        self.assertIn('/nonexistent/words.txt', out)
        scanner.assert_not_called()

    def test_wordlist_without_dirs_is_an_error(self):
        code, out, scanner = self._run('--target', '10.0.0.1', '--wordlist', 'words.txt')
        self.assertEqual(code, 1)
        self.assertIn('--wordlist only applies to --dirs', out)
        scanner.assert_not_called()

    def test_a_url_that_is_not_http_or_https_stops_before_any_request(self):
        for url in ('ftp://10.0.0.1/', 'example.com', 'http://'):
            with self.subTest(url=url):
                code, out, scanner = self._run('--dirs', url)
                self.assertEqual(code, 1)
                self.assertIn('must be an http:// or https:// URL', out)
                scanner.assert_not_called()

    def test_invalid_settings_are_reported_as_a_config_error(self):
        with patch.object(sys, 'argv', ['main.py', '--dirs', 'http://10.0.0.1/']), \
                patch('modules.dir_scan.DirectoryScanner', side_effect=ValueError('dirs_rate must be ...')), \
                redirect_stdout(io.StringIO()) as out, self.assertRaises(SystemExit) as exit:
            main.main()
        self.assertEqual(exit.exception.code, 1)
        self.assertIn('Error in config.yaml: dirs_rate must be', out.getvalue())

    def test_an_incomplete_scan_exits_non_zero(self):
        report = DirectoryReport('http://10.0.0.1/', [], ['stopped after 3 connection errors in a row'])
        code, out, _ = self._run('--dirs', 'http://10.0.0.1/', report=report)
        self.assertEqual(code, 1)
        self.assertIn('stopped after 3 connection errors', out)


if __name__ == '__main__':
    unittest.main()

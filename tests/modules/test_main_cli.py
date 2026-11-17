import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from unittest.mock import MagicMock, patch

sys.modules.setdefault('nmap', MagicMock())

import main  # noqa: E402
from domain.findings import Cve, Finding  # noqa: E402
from modules.cloud import BucketReport  # noqa: E402

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
        reporter.assert_called_once_with(SERVICES)

    def test_exploit_flag_runs_exploitation(self):
        exploiter, reporter = self._run('--exploit')
        exploiter.assert_called_once_with(SERVICES)
        reporter.assert_called_once_with(SERVICES)


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


if __name__ == '__main__':
    unittest.main()

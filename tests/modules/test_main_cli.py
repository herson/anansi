import sys
import unittest
from unittest.mock import MagicMock, patch

sys.modules.setdefault('nmap', MagicMock())

import main  # noqa: E402
from domain.findings import Finding  # noqa: E402

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


if __name__ == '__main__':
    unittest.main()

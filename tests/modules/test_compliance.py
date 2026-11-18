import unittest

from domain.findings import Cve, Finding
from modules.compliance import ComplianceMapper, FRAMEWORK_MAP


def _finding(host='10.0.0.1', port=80, service='http', cves=()):
    return Finding(host, port, 'tcp', service, '', '1.0', tuple(cves))


def _controls(findings, framework):
    return [f['control'] for f in ComplianceMapper(findings).map(frameworks=[framework])[framework]]


class TestComplianceMapper(unittest.TestCase):

    def test_map_returns_all_frameworks_by_default(self):
        output = ComplianceMapper([_finding()]).map()
        self.assertEqual(set(output.keys()), set(FRAMEWORK_MAP.keys()))

    def test_map_filters_to_requested_frameworks(self):
        output = ComplianceMapper([_finding()]).map(frameworks=['PCI-DSS'])
        self.assertEqual(set(output), {'PCI-DSS'})

    def test_unknown_framework_is_skipped(self):
        self.assertEqual(ComplianceMapper([_finding()]).map(frameworks=['UNKNOWN']), {})

    def test_open_port_triggers_open_ports_control(self):
        self.assertTrue(any('SC-7' in c for c in _controls([_finding(port=443, service='https')], 'NIST')))

    def test_insecure_service_triggers_unencrypted_control(self):
        controls = _controls([_finding(port=21, service='ftp')], 'HIPAA')
        self.assertTrue(any('164.312(e)(2)' in c for c in controls))

    def test_critical_cve_triggers_cve_critical_control(self):
        cve = Cve('CVE-2023-0001', 9.8, 'CRITICAL', 'test')
        self.assertTrue(any('6.3.3' in c for c in _controls([_finding(cves=[cve])], 'PCI-DSS')))

    def test_high_cve_triggers_cve_high_control(self):
        cve = Cve('CVE-2023-0002', 7.5, 'HIGH', 'test')
        self.assertTrue(any('SI-2' in c for c in _controls([_finding(cves=[cve])], 'NIST')))

    def test_each_control_triggered_at_most_once(self):
        findings = [_finding(port=80), _finding(port=8080), _finding(host='10.0.0.2', port=80)]
        controls = _controls(findings, 'NIST')
        self.assertEqual(len([c for c in controls if 'SC-7' in c]), 1)

    def test_evidence_names_the_host(self):
        cve = Cve('CVE-2023-0001', 9.8, 'CRITICAL', 'test')
        output = ComplianceMapper([_finding(host='10.0.0.7', port=21, service='ftp', cves=[cve])]).map()
        for framework, findings in output.items():
            for item in findings:
                with self.subTest(framework=framework, control=item['control']):
                    self.assertIn('10.0.0.7:21/tcp', item['evidence'])

    def test_empty_results_produce_no_findings(self):
        for fw, findings in ComplianceMapper([]).map().items():
            self.assertEqual(findings, [], msg=f"{fw} should have no findings")


if __name__ == '__main__':
    unittest.main()

import unittest
from modules.compliance import ComplianceMapper, FRAMEWORK_MAP


class TestComplianceMapper(unittest.TestCase):

    def _make_results(self, port=80, service='http', cves=None):
        return {port: {'service': service, 'version': '1.0', 'cves': cves or []}}

    def test_map_returns_all_frameworks_by_default(self):
        mapper = ComplianceMapper(self._make_results())
        output = mapper.map()
        self.assertEqual(set(output.keys()), set(FRAMEWORK_MAP.keys()))

    def test_map_filters_to_requested_frameworks(self):
        mapper = ComplianceMapper(self._make_results())
        output = mapper.map(frameworks=['PCI-DSS'])
        self.assertIn('PCI-DSS', output)
        self.assertNotIn('HIPAA', output)
        self.assertNotIn('NIST', output)

    def test_unknown_framework_is_skipped(self):
        mapper = ComplianceMapper(self._make_results())
        output = mapper.map(frameworks=['UNKNOWN'])
        self.assertEqual(output, {})

    def test_open_port_triggers_open_ports_control(self):
        mapper = ComplianceMapper(self._make_results(port=443, service='https'))
        findings = mapper.map(frameworks=['NIST'])['NIST']
        controls = [f['control'] for f in findings]
        self.assertTrue(any('SC-7' in c for c in controls))

    def test_insecure_service_triggers_unencrypted_control(self):
        mapper = ComplianceMapper(self._make_results(port=21, service='ftp'))
        findings = mapper.map(frameworks=['HIPAA'])['HIPAA']
        controls = [f['control'] for f in findings]
        self.assertTrue(any('164.312(e)(2)' in c for c in controls))

    def test_critical_cve_triggers_cve_critical_control(self):
        cves = [{'id': 'CVE-2023-0001', 'score': 9.8, 'severity': 'CRITICAL', 'description': 'test'}]
        mapper = ComplianceMapper(self._make_results(port=80, service='http', cves=cves))
        findings = mapper.map(frameworks=['PCI-DSS'])['PCI-DSS']
        controls = [f['control'] for f in findings]
        self.assertTrue(any('6.3.3' in c for c in controls))

    def test_high_cve_triggers_cve_high_control(self):
        cves = [{'id': 'CVE-2023-0002', 'score': 7.5, 'severity': 'HIGH', 'description': 'test'}]
        mapper = ComplianceMapper(self._make_results(port=80, service='http', cves=cves))
        findings = mapper.map(frameworks=['NIST'])['NIST']
        controls = [f['control'] for f in findings]
        self.assertTrue(any('SI-2' in c for c in controls))

    def test_each_control_triggered_at_most_once(self):
        results = {
            80: {'service': 'http', 'cves': []},
            8080: {'service': 'http', 'cves': []},
        }
        mapper = ComplianceMapper(results)
        findings = mapper.map(frameworks=['NIST'])['NIST']
        open_port_findings = [f for f in findings if 'SC-7' in f['control']]
        self.assertEqual(len(open_port_findings), 1)

    def test_empty_results_produce_no_findings(self):
        mapper = ComplianceMapper({})
        for fw, findings in mapper.map().items():
            self.assertEqual(findings, [], msg=f"{fw} should have no findings")


if __name__ == '__main__':
    unittest.main()

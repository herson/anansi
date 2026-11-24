import ast
import dataclasses
import json
import sys
import unittest
from pathlib import Path

from domain.findings import Cve, Finding, findings_from_json, findings_to_json

DOMAIN = Path(__file__).resolve().parents[2] / "domain"

CVE = Cve(id="CVE-2021-41773", score=9.8, severity="CRITICAL", description="Path traversal")


def finding(**overrides):
    values = dict(host="10.0.0.1", port=80, protocol="tcp", service="http",
                  product="Apache httpd", version="2.4.49")
    values.update(overrides)
    return Finding(**values)


class TestFinding(unittest.TestCase):

    def test_has_no_cves_by_default(self):
        self.assertEqual(finding().cves, ())

    def test_is_immutable(self):
        with self.assertRaises(dataclasses.FrozenInstanceError):
            finding().port = 443

    def test_same_port_on_different_hosts_are_different_findings(self):
        self.assertNotEqual(finding(host="10.0.0.1"), finding(host="10.0.0.2"))

    def test_same_port_on_different_protocols_are_different_findings(self):
        self.assertNotEqual(finding(protocol="tcp", port=53), finding(protocol="udp", port=53))


class TestFindingsToJson(unittest.TestCase):

    def test_produces_a_list_of_plain_objects(self):
        data = findings_to_json([finding(cves=(CVE,)), finding(host="10.0.0.2", cves=())])
        self.assertEqual(data, [
            {"host": "10.0.0.1", "port": 80, "protocol": "tcp", "service": "http",
             "product": "Apache httpd", "version": "2.4.49",
             "cves": [{"id": "CVE-2021-41773", "score": 9.8, "severity": "CRITICAL",
                       "description": "Path traversal"}]},
            {"host": "10.0.0.2", "port": 80, "protocol": "tcp", "service": "http",
             "product": "Apache httpd", "version": "2.4.49", "cves": []},
        ])

    def test_round_trips_through_json(self):
        data = findings_to_json([finding(cves=(CVE,))])
        self.assertEqual(json.loads(json.dumps(data)), data)

    def test_empty_list(self):
        self.assertEqual(findings_to_json([]), [])


class TestFindingsFromJson(unittest.TestCase):

    def test_rebuilds_the_findings_that_were_stored(self):
        findings = [finding(cves=(CVE,)), finding(host="10.0.0.2", port=22, service="ssh")]
        stored = json.loads(json.dumps(findings_to_json(findings)))
        self.assertEqual(findings_from_json(stored), findings)

    def test_empty_list(self):
        self.assertEqual(findings_from_json([]), [])


class TestDomainHasNoInfrastructureDependencies(unittest.TestCase):

    def test_domain_imports_only_the_standard_library_and_itself(self):
        for path in DOMAIN.glob("*.py"):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    roots = [a.name.split(".")[0] for a in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    roots = [node.module.split(".")[0]]
                else:
                    continue
                for root in roots:
                    with self.subTest(file=path.name, module=root):
                        self.assertTrue(root in sys.stdlib_module_names or root == "domain")


if __name__ == "__main__":
    unittest.main()

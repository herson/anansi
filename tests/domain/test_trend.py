import unittest

from domain.findings import Cve, Finding
from domain.trend import SEVERITIES, count_findings


def cve(severity, id_="CVE-2021-0001"):
    return Cve(id_, None, severity, "")


def finding(host="10.0.0.1", port=80, protocol="tcp", cves=()):
    return Finding(host, port, protocol, "http", "Apache httpd", "2.4.49", tuple(cves))


class TestPortsAndHosts(unittest.TestCase):

    def test_counts_open_ports_by_host_protocol_and_port_and_hosts_with_any(self):
        counts = count_findings([finding(), finding(port=443), finding(port=53, protocol="udp"),
                                 finding(host="10.0.0.2")], cves_complete=False)
        self.assertEqual(counts.open_ports, 4)
        self.assertEqual(counts.hosts, 2)

    def test_no_findings(self):
        counts = count_findings([], cves_complete=True)
        self.assertEqual((counts.open_ports, counts.hosts), (0, 0))
        self.assertEqual(counts.cves, dict.fromkeys(SEVERITIES, 0))


class TestCvesBySeverity(unittest.TestCase):

    def test_counts_each_cve_once_per_finding_it_appears_on(self):
        shared = cve("CRITICAL")
        counts = count_findings([finding(cves=[shared]), finding(host="10.0.0.2", cves=[shared])],
                                cves_complete=True)
        self.assertEqual(counts.cves["critical"], 2)

    def test_severities_match_in_any_case_and_the_rest_count_as_other(self):
        counts = count_findings([finding(cves=[cve("HIGH"), cve("medium"), cve("Low"), cve("NONE"),
                                               cve("UNKNOWN"), cve("")])], cves_complete=True)
        self.assertEqual(counts.cves, {"critical": 0, "high": 1, "medium": 1, "low": 1, "other": 3})

    def test_cves_are_not_counted_when_the_scans_lookup_did_not_complete(self):
        # A failed lookup leaves CVE lists empty; drawing that as zero would invent a drop (ADR-0014).
        counts = count_findings([finding(cves=[cve("HIGH")])], cves_complete=False)
        self.assertIsNone(counts.cves)
        self.assertEqual(counts.open_ports, 1)

    def test_severities_are_listed_most_severe_first(self):
        self.assertEqual(SEVERITIES, ("critical", "high", "medium", "low", "other"))


if __name__ == "__main__":
    unittest.main()

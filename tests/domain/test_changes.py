import unittest

from domain.changes import (CveChange, HostNotSeen, ScanOptions, ServiceChange, compare,
                            comparable, same_network)
from domain.findings import Cve, Finding

OLD_CVE = Cve("CVE-2021-41773", 7.5, "HIGH", "Path traversal")
NEW_CVE = Cve("CVE-2021-42013", 9.8, "CRITICAL", "Path traversal and RCE")


def finding(host="10.0.0.1", port=80, protocol="tcp", service="http", product="Apache httpd",
            version="2.4.49", cves=()):
    return Finding(host, port, protocol, service, product, version, tuple(cves))


def options(nmap_arguments="-sT -sV", cve_lookup=False, cve_lookup_complete=False):
    return ScanOptions(nmap_arguments, cve_lookup, cve_lookup_complete)


class TestComparableScans(unittest.TestCase):

    def test_scans_that_ran_the_same_way_are_comparable(self):
        self.assertTrue(comparable(options(cve_lookup=True, cve_lookup_complete=True),
                                   options(cve_lookup=True, cve_lookup_complete=False)))

    def test_different_nmap_arguments_are_not_comparable(self):
        # A root scan (-sS) and a non-root scan (-sT), or a changed exclude list, can find different ports.
        self.assertFalse(comparable(options("-sS -sV"), options("-sT -sV")))
        self.assertFalse(comparable(options("-sT -sV"), options("-sT -sV -Pn --exclude-ports 22")))

    def test_a_scan_with_the_cve_lookup_is_not_comparable_with_one_without(self):
        self.assertFalse(comparable(options(cve_lookup=True), options(cve_lookup=False)))


class TestSameNetwork(unittest.TestCase):

    def test_different_spellings_of_one_network_match(self):
        self.assertTrue(same_network("10.0.0.0/24", "10.0.0.7/24"))
        self.assertTrue(same_network("10.0.0.5", "10.0.0.5/32"))
        self.assertTrue(same_network("2001:db8::1", "2001:0db8:0000::1"))

    def test_different_networks_do_not_match(self):
        self.assertFalse(same_network("10.0.0.5", "10.0.0.0/24"))
        self.assertFalse(same_network("10.0.0.5", "10.0.0.6"))

    def test_a_target_that_is_not_a_network_matches_nothing(self):
        self.assertFalse(same_network("not a target", "not a target"))


class TestPorts(unittest.TestCase):

    def test_no_differences_means_no_changes(self):
        changes = compare([finding()], [finding()], compare_cves=True)
        self.assertFalse(changes.any())

    def test_a_port_open_now_and_not_before_is_opened(self):
        ssh = finding(port=22, service="ssh", product="OpenSSH", version="8.2")
        changes = compare([finding()], [finding(), ssh], compare_cves=False)
        self.assertEqual(changes.opened, [ssh])
        self.assertTrue(changes.any())

    def test_a_port_gone_from_a_host_that_still_answers_is_closed(self):
        ssh = finding(port=22, service="ssh")
        changes = compare([finding(), ssh], [finding()], compare_cves=False)
        self.assertEqual(changes.closed, [ssh])
        self.assertEqual(changes.hosts_not_seen, [])

    def test_ports_are_matched_by_host_protocol_and_port(self):
        changes = compare([finding(host="10.0.0.1"), finding(host="10.0.0.2", protocol="udp", port=53)],
                          [finding(host="10.0.0.1"), finding(host="10.0.0.2", protocol="tcp", port=53)],
                          compare_cves=False)
        self.assertEqual([(f.protocol, f.port) for f in changes.opened], [("tcp", 53)])
        self.assertEqual([(f.protocol, f.port) for f in changes.closed], [("udp", 53)])


class TestHostsNotSeen(unittest.TestCase):

    def test_a_host_with_no_open_ports_now_is_not_seen_rather_than_closed(self):
        gone = [finding(host="10.0.0.2", port=22, service="ssh"), finding(host="10.0.0.2")]
        changes = compare([finding(), *gone], [finding()], compare_cves=False)
        self.assertEqual(changes.closed, [])
        self.assertEqual(changes.hosts_not_seen, [HostNotSeen("10.0.0.2", tuple(gone))])
        self.assertTrue(changes.any())


class TestServices(unittest.TestCase):

    def test_a_different_service_product_or_version_is_a_change(self):
        for after in (finding(service="https"), finding(product="nginx"), finding(version="2.4.51")):
            with self.subTest(after=after):
                changes = compare([finding()], [after], compare_cves=False)
                self.assertEqual(changes.changed, [ServiceChange(finding(), after)])


class TestCves(unittest.TestCase):

    def test_a_cve_listed_now_and_not_before_is_added_even_with_the_same_version(self):
        changes = compare([finding(cves=[OLD_CVE])], [finding(cves=[OLD_CVE, NEW_CVE])], compare_cves=True)
        after = finding(cves=[OLD_CVE, NEW_CVE])
        self.assertEqual(changes.cves_added, [CveChange(after, (NEW_CVE,))])
        self.assertEqual(changes.cves_removed, [])

    def test_a_cve_gone_after_a_version_change_is_removed(self):
        before, after = finding(cves=[OLD_CVE]), finding(version="2.4.51")
        changes = compare([before], [after], compare_cves=True)
        self.assertEqual(changes.cves_removed, [CveChange(after, (OLD_CVE,))])

    def test_a_cve_gone_with_the_same_product_and_version_is_not_reported(self):
        # NVD keyword search returns its top 5 matches; a new CVE can push an old one out.
        changes = compare([finding(cves=[OLD_CVE])], [finding(cves=[NEW_CVE])], compare_cves=True)
        self.assertEqual(changes.cves_removed, [])
        self.assertEqual([c.cves for c in changes.cves_added], [(NEW_CVE,)])

    def test_cves_are_ignored_when_they_cannot_be_compared(self):
        changes = compare([finding(cves=[OLD_CVE])], [finding(version="2.4.51", cves=[NEW_CVE])],
                          compare_cves=False)
        self.assertEqual(changes.cves_added, [])
        self.assertEqual(changes.cves_removed, [])
        self.assertEqual(len(changes.changed), 1)

    def test_a_cve_change_alone_does_not_count_as_a_service_change(self):
        changes = compare([finding()], [finding(cves=[NEW_CVE])], compare_cves=True)
        self.assertEqual(changes.changed, [])


if __name__ == "__main__":
    unittest.main()

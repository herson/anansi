import unittest
from unittest.mock import MagicMock, patch
import sys

# Stub dnspython sub-modules before importing dns_enum
_dns_stub = MagicMock()
for _mod in ('dns', 'dns.resolver', 'dns.zone', 'dns.query', 'dns.exception'):
    sys.modules.setdefault(_mod, _dns_stub)

from modules.dns_enum import DNSEnumerator, RECORD_TYPES


class TestDNSEnumerator(unittest.TestCase):

    def setUp(self):
        self.resolver_mock = MagicMock()
        patcher = patch('modules.dns_enum.dns.resolver.Resolver', return_value=self.resolver_mock)
        self.addCleanup(patcher.stop)
        patcher.start()
        self.enumerator = DNSEnumerator('example.com')
        self.enumerator._resolver = self.resolver_mock

    def test_lookup_records_returns_all_record_types(self):
        self.resolver_mock.resolve.return_value = [MagicMock(__str__=lambda s: '1.2.3.4')]
        records = self.enumerator.lookup_records()
        self.assertEqual(set(records.keys()), set(RECORD_TYPES))

    def test_lookup_records_handles_resolution_failure(self):
        self.resolver_mock.resolve.side_effect = Exception('nxdomain')
        records = self.enumerator.lookup_records()
        for rtype in RECORD_TYPES:
            self.assertEqual(records[rtype], [])

    def test_lookup_records_converts_answers_to_strings(self):
        answer = MagicMock()
        answer.__str__ = lambda s: '93.184.216.34'
        self.resolver_mock.resolve.return_value = [answer]
        records = self.enumerator.lookup_records()
        self.assertIn('93.184.216.34', records['A'])

    def test_brute_force_returns_resolved_subdomains(self):
        def _resolve(name, rtype):
            if name == 'www.example.com':
                return MagicMock()
            raise Exception('nxdomain')

        self.resolver_mock.resolve.side_effect = _resolve
        enumerator = DNSEnumerator('example.com', wordlist=['www', 'mail'])
        enumerator._resolver = self.resolver_mock
        found = enumerator.brute_force_subdomains()
        self.assertEqual(found, ['www.example.com'])

    def test_brute_force_returns_empty_when_none_resolve(self):
        self.resolver_mock.resolve.side_effect = Exception('nxdomain')
        enumerator = DNSEnumerator('example.com', wordlist=['www', 'mail'])
        enumerator._resolver = self.resolver_mock
        self.assertEqual(enumerator.brute_force_subdomains(), [])

    def test_zone_transfer_returns_empty_on_ns_failure(self):
        self.resolver_mock.resolve.side_effect = Exception('no NS')
        result = self.enumerator.attempt_zone_transfer()
        self.assertEqual(result, {})

    def test_zone_transfer_records_empty_list_on_axfr_failure(self):
        ns_mock = MagicMock()
        ns_mock.__str__ = lambda s: 'ns1.example.com.'
        self.resolver_mock.resolve.return_value = [ns_mock]

        with patch('modules.dns_enum.dns.zone.from_xfr', side_effect=Exception('AXFR refused')):
            result = self.enumerator.attempt_zone_transfer()

        self.assertIn('ns1.example.com', result)
        self.assertEqual(result['ns1.example.com'], [])

    def test_enumerate_returns_expected_keys(self):
        self.resolver_mock.resolve.side_effect = Exception('nxdomain')
        result = self.enumerator.enumerate()
        self.assertIn('domain', result)
        self.assertIn('records', result)
        self.assertIn('subdomains', result)
        self.assertIn('zone_transfer', result)
        self.assertEqual(result['domain'], 'example.com')

    def test_domain_trailing_dot_stripped(self):
        enumerator = DNSEnumerator('example.com.')
        self.assertEqual(enumerator.domain, 'example.com')

    def test_custom_wordlist_is_used(self):
        self.resolver_mock.resolve.side_effect = Exception('nxdomain')
        enumerator = DNSEnumerator('example.com', wordlist=['custom'])
        enumerator._resolver = self.resolver_mock
        enumerator.brute_force_subdomains()
        call_args = [str(c) for c in self.resolver_mock.resolve.call_args_list]
        self.assertTrue(any('custom.example.com' in c for c in call_args))


if __name__ == '__main__':
    unittest.main()

"""DNS enumeration: record lookup, subdomain brute-force, zone transfer attempts."""
import logging

import dns.exception
import dns.query
import dns.resolver
import dns.zone

RECORD_TYPES = ('A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA')

DEFAULT_WORDLIST = [
    'www', 'mail', 'ftp', 'admin', 'vpn', 'api', 'dev', 'staging',
    'test', 'portal', 'remote', 'webmail', 'smtp', 'pop', 'imap',
    'ns1', 'ns2', 'cdn', 'static', 'beta', 'shop', 'secure', 'git',
]


class DNSEnumerator:
    def __init__(self, domain: str, wordlist=None):
        self.domain = domain.rstrip('.')
        self.wordlist = wordlist if wordlist is not None else DEFAULT_WORDLIST
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = 2
        self._resolver.lifetime = 4

    def enumerate(self) -> dict:
        """Run full DNS enumeration and return a structured results dict."""
        return {
            'domain':        self.domain,
            'records':       self.lookup_records(),
            'subdomains':    self.brute_force_subdomains(),
            'zone_transfer': self.attempt_zone_transfer(),
        }

    def lookup_records(self) -> dict:
        """Query standard DNS record types for the domain."""
        records = {}
        for rtype in RECORD_TYPES:
            try:
                answers = self._resolver.resolve(self.domain, rtype)
                records[rtype] = [str(r) for r in answers]
            except Exception:
                records[rtype] = []
        return records

    def brute_force_subdomains(self) -> list:
        """Test each wordlist entry as a subdomain; return those that resolve."""
        found = []
        for word in self.wordlist:
            subdomain = f"{word}.{self.domain}"
            try:
                self._resolver.resolve(subdomain, 'A')
                found.append(subdomain)
            except Exception:
                pass
        return found

    def attempt_zone_transfer(self) -> dict:
        """Try AXFR on each NS; record names returned on success."""
        results = {}
        try:
            ns_answers = self._resolver.resolve(self.domain, 'NS')
        except Exception:
            return results

        for ns_rdata in ns_answers:
            ns = str(ns_rdata).rstrip('.')
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(ns, self.domain, timeout=5))
                results[ns] = [str(n) for n in zone.nodes.keys()]
                logging.warning("Zone transfer succeeded for %s via %s", self.domain, ns)
            except Exception:
                results[ns] = []

        return results

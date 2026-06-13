import logging
import time

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnLookup:
    def __init__(self, api_key=None):
        """
        Args:
            api_key: Optional NVD API key. Raises the rate limit from 5 to 50
                     requests per 30 seconds and shortens the inter-request delay.
        """
        self.api_key = api_key
        self._delay = 0.6 if api_key else 6  # seconds between requests
        self.session = requests.Session()
        if api_key:
            self.session.headers['apiKey'] = api_key

    def lookup(self, service, version):
        """Query NVD for CVEs matching service + version. Returns a list of CVE dicts."""
        query = f"{service} {version}".strip()
        if not query:
            return []

        try:
            resp = self.session.get(
                NVD_API_URL,
                params={'keywordSearch': query, 'resultsPerPage': 5},
                timeout=10,
            )
            resp.raise_for_status()
            return [self._parse_cve(item['cve']) for item in resp.json().get('vulnerabilities', [])]
        except requests.RequestException as e:
            logging.error("CVE lookup failed for '%s': %s", query, e)
            return []

    def enrich(self, services):
        """Return a copy of services with a 'cves' list added to each entry."""
        enriched = {}
        for i, (port, info) in enumerate(services.items()):
            if i > 0:
                time.sleep(self._delay)
            cves = self.lookup(info.get('service', ''), info.get('version', ''))
            enriched[port] = {**info, 'cves': cves}
        return enriched

    @staticmethod
    def _parse_cve(cve):
        """Extract id, CVSS score, severity, and description from a raw NVD CVE object."""
        desc = next(
            (d['value'] for d in cve.get('descriptions', []) if d['lang'] == 'en'),
            'No description available',
        )
        score, severity = None, 'UNKNOWN'
        metrics = cve.get('metrics', {})
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if metrics.get(key):
                cvss = metrics[key][0].get('cvssData', {})
                score = cvss.get('baseScore')
                severity = cvss.get('baseSeverity', 'UNKNOWN')
                break

        return {
            'id': cve.get('id', ''),
            'score': score,
            'severity': severity,
            'description': desc[:300],
        }

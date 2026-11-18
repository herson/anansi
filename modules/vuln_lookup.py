import logging
import time
from dataclasses import replace
from typing import Any

import requests

from domain.findings import Cve, Finding

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


class VulnLookup:
    def __init__(self, api_key: str | None = None) -> None:
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

    def lookup(self, service: str, version: str) -> list[Cve]:
        """Query NVD for CVEs matching service + version."""
        query = f"{service} {version}".strip()
        if not query:
            return []

        params: dict[str, str | int] = {'keywordSearch': query, 'resultsPerPage': 5}
        try:
            resp = self.session.get(NVD_API_URL, params=params, timeout=10)
            resp.raise_for_status()
            return [self._parse_cve(item['cve']) for item in resp.json().get('vulnerabilities', [])]
        except requests.RequestException as e:
            logging.error("CVE lookup failed for '%s': %s", query, e)
            return []

    def enrich(self, findings: list[Finding]) -> list[Finding]:
        """Return the findings with their CVEs attached.

        Findings without a detected version are not looked up: a bare service
        name matches unrelated CVEs and would report false positives.
        """
        enriched = []
        requested = False
        for finding in findings:
            if not finding.version:
                enriched.append(finding)
                continue
            if requested:
                time.sleep(self._delay)
            requested = True
            cves = self.lookup(finding.product or finding.service, finding.version)
            enriched.append(replace(finding, cves=tuple(cves)))
        return enriched

    @staticmethod
    def _parse_cve(cve: dict[str, Any]) -> Cve:
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

        return Cve(id=cve.get('id', ''), score=score, severity=severity, description=desc[:300])

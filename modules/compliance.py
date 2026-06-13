"""Maps scan findings to PCI-DSS, HIPAA, and NIST framework controls."""

INSECURE_SERVICES = {'ftp', 'telnet', 'http', 'rsh', 'rlogin', 'rexec', 'tftp', 'snmp'}

_PCI_DSS = {
    'open_ports':   'PCI-DSS 1.3 – Prohibit direct public access between the Internet and the cardholder data environment',
    'unencrypted':  'PCI-DSS 4.2 – Never send unprotected PANs over open, public networks',
    'cve_critical': 'PCI-DSS 6.3.3 – Protect all system components by installing applicable security patches/updates',
    'cve_high':     'PCI-DSS 6.3.3 – Protect all system components by installing applicable security patches/updates',
}

_HIPAA = {
    'open_ports':   'HIPAA § 164.312(e)(1) – Technical security measures to guard against unauthorized access to ePHI',
    'unencrypted':  'HIPAA § 164.312(e)(2)(ii) – Encryption of ePHI in transit',
    'cve_critical': 'HIPAA § 164.306(a)(1) – Protect against reasonably anticipated threats to the security of ePHI',
    'cve_high':     'HIPAA § 164.306(a)(1) – Protect against reasonably anticipated threats to the security of ePHI',
}

_NIST = {
    'open_ports':   'NIST SP 800-53 SC-7 – Boundary Protection',
    'unencrypted':  'NIST SP 800-53 SC-8 – Transmission Confidentiality and Integrity',
    'cve_critical': 'NIST SP 800-53 SI-2 – Flaw Remediation (Critical severity)',
    'cve_high':     'NIST SP 800-53 SI-2 – Flaw Remediation (High severity)',
}

FRAMEWORK_MAP = {
    'PCI-DSS': _PCI_DSS,
    'HIPAA':   _HIPAA,
    'NIST':    _NIST,
}


class ComplianceMapper:
    def __init__(self, results: dict):
        """
        Args:
            results: Dict of {port: {service, version, cves, ...}} scan findings.
        """
        self.results = results

    def map(self, frameworks=None) -> dict:
        """Return triggered controls per framework.

        Args:
            frameworks: List of framework names to evaluate. Defaults to all three.
        Returns:
            Dict keyed by framework name; each value is a list of
            {'control': str, 'evidence': str} dicts.
        """
        if frameworks is None:
            frameworks = list(FRAMEWORK_MAP.keys())

        output = {}
        for fw in frameworks:
            controls = FRAMEWORK_MAP.get(fw)
            if controls is None:
                continue
            output[fw] = self._evaluate(controls)
        return output

    def _evaluate(self, controls: dict) -> list:
        """Return list of triggered control findings for a single framework."""
        triggered = []
        seen = set()

        def _add(key, evidence):
            if key not in seen and key in controls:
                seen.add(key)
                triggered.append({'control': controls[key], 'evidence': evidence})

        for port, info in self.results.items():
            service = (info.get('service') or '').lower()

            if service:
                _add('open_ports', f"Port {port} ({service}) is open")

            if service in INSECURE_SERVICES:
                _add('unencrypted', f"Port {port} runs {service}, an unencrypted protocol")

            for cve in info.get('cves', []):
                severity = (cve.get('severity') or '').upper()
                if severity == 'CRITICAL':
                    _add('cve_critical', f"{cve['id']} (CVSS {cve.get('score', 'N/A')}) on port {port}")
                elif severity == 'HIGH':
                    _add('cve_high', f"{cve['id']} (CVSS {cve.get('score', 'N/A')}) on port {port}")

        return triggered

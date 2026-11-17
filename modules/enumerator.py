from typing import Any

from domain.findings import Finding, Protocol

_PROTOCOLS: tuple[Protocol, ...] = ("tcp", "udp")


class ServiceEnumerator:
    def __init__(self, scan_data: dict[str, Any]) -> None:
        """
        Args:
            scan_data: Raw dict returned by NetworkScanner.scan().
        """
        self.scan_data = scan_data

    def enumerate(self) -> list[Finding]:
        """Return one Finding per host, port and protocol in the nmap results."""
        print("Enumerating services...")
        findings = []
        for host, sections in self.scan_data.get('scan', {}).items():
            for protocol in _PROTOCOLS:
                ports = sections.get(protocol)
                if not isinstance(ports, dict):
                    continue
                for port, entry in ports.items():
                    findings.append(Finding(
                        host=host,
                        port=int(port),
                        protocol=protocol,
                        service=entry.get('name', ''),
                        product=entry.get('product', ''),
                        version=entry.get('version', ''),
                    ))
        return findings

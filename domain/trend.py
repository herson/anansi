"""Per-scan counts behind the status-over-time charts (ADR-0014)."""
from dataclasses import dataclass
from typing import Sequence

from domain.findings import Finding

SEVERITIES = ("critical", "high", "medium", "low", "other")


@dataclass(frozen=True)
class ScanCounts:
    open_ports: int
    hosts: int
    cves: dict[str, int] | None  # by severity; None if the scan's CVE lookup didn't complete


@dataclass(frozen=True)
class SeriesPoint:
    scan_id: int
    completed_at: str
    counts: ScanCounts


@dataclass(frozen=True)
class StatusSeries:
    """Comparable scans of one target, oldest first."""
    target: str
    cve_lookup: bool
    points: list[SeriesPoint]


def count_findings(findings: Sequence[Finding], cves_complete: bool) -> ScanCounts:
    """Open ports, hosts with any, and CVEs by severity, each CVE counted once per finding."""
    cves = None
    if cves_complete:
        cves = dict.fromkeys(SEVERITIES, 0)
        for f in findings:
            for c in f.cves:
                severity = c.severity.lower()
                cves[severity if severity in cves else "other"] += 1
    return ScanCounts(open_ports=len(findings), hosts=len({f.host for f in findings}), cves=cves)

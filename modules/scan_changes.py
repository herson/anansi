"""Read comparable scans from history: changes since the last one (ADR-0013) and status over time (ADR-0014)."""
import json
from dataclasses import asdict
from itertools import islice
from typing import Any, Iterator

from domain.changes import ScanOptions, comparable, compare, same_network
from domain.findings import findings_from_json
from domain.trend import SeriesPoint, StatusSeries, count_findings
from modules.database import ScanDatabase

SERIES_LIMIT = 30


def changes_since_previous_scan(db: ScanDatabase, scan_id: int) -> dict[str, Any] | None:
    """Changes since the previous comparable scan, as JSON-ready data; None if the scan doesn't exist."""
    scan = db.get_scan(scan_id)
    if scan is None:
        return None
    if scan['status'] == 'running':
        return _not_comparable(scan_id, "This scan hasn't finished.")
    if scan['status'] != 'completed':
        return _not_comparable(scan_id, "This scan failed.")
    if scan['options'] is None:
        return _not_comparable(scan_id, "This scan was saved before Anansi recorded how scans ran.")

    options = ScanOptions(**json.loads(scan['options']))
    baseline = next(_earlier_comparable_scans(db, scan, options), None)
    if baseline is None:
        return _not_comparable(scan_id, "No earlier scan of this target ran the same way.")

    baseline_options = ScanOptions(**json.loads(baseline['options']))
    cves_reason = _why_cves_are_not_compared(baseline_options, options)
    previous = db.get_scan(baseline['id'])
    assert previous is not None  # listed a moment ago, and scans are never deleted
    changes = compare(findings_from_json(json.loads(previous['results'])),
                      findings_from_json(json.loads(scan['results'])),
                      compare_cves=cves_reason is None)
    return {
        'scan_id': scan_id,
        'comparable': True,
        'reason': None,
        'baseline': {'id': baseline['id'], 'completed_at': baseline['completed_at']},
        'cves_compared': cves_reason is None,
        'cves_reason': cves_reason,
        'changes': asdict(changes),
    }


def status_over_time(db: ScanDatabase, scan_id: int) -> StatusSeries | None:
    """The scan and the earlier scans comparable with it, oldest first; None if fewer than two."""
    scan = db.get_scan(scan_id)
    if scan is None or scan['status'] != 'completed' or scan['options'] is None:
        return None
    options = ScanOptions(**json.loads(scan['options']))
    earlier = list(islice(_earlier_comparable_scans(db, scan, options), SERIES_LIMIT - 1))
    if not earlier:
        return None
    stored = (db.get_scan(row['id']) for row in reversed(earlier))
    points = [_point(s) for s in stored if s is not None] + [_point(scan)]
    return StatusSeries(scan['target'], options.cve_lookup, points)


def _earlier_comparable_scans(db: ScanDatabase, scan: dict[str, Any], options: ScanOptions) -> Iterator[dict[str, Any]]:
    """Earlier completed scans of the same network that ran the same way, newest first (no results)."""
    for row in db.earlier_completed_scans(scan['id']):
        row_options = ScanOptions(**json.loads(row['options']))
        if same_network(row['target'], scan['target']) and comparable(row_options, options):
            yield row


def _point(scan: dict[str, Any]) -> SeriesPoint:
    options = ScanOptions(**json.loads(scan['options']))
    findings = findings_from_json(json.loads(scan['results']))
    return SeriesPoint(scan['id'], scan['completed_at'], count_findings(findings, options.cve_lookup_complete))


def _why_cves_are_not_compared(baseline: ScanOptions, current: ScanOptions) -> str | None:
    if not current.cve_lookup:
        return "These scans didn't look up CVEs."
    if not (baseline.cve_lookup_complete and current.cve_lookup_complete):
        return "A CVE lookup failed in this scan or the one before, so CVEs weren't compared."
    return None


def _not_comparable(scan_id: int, reason: str) -> dict[str, Any]:
    return {'scan_id': scan_id, 'comparable': False, 'reason': reason, 'baseline': None,
            'cves_compared': False, 'cves_reason': None, 'changes': None}

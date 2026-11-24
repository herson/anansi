"""Find a scan's baseline in history and report what changed since (ADR-0013)."""
import json
from dataclasses import asdict
from typing import Any

from domain.changes import ScanOptions, comparable, compare, same_network
from domain.findings import findings_from_json
from modules.database import ScanDatabase


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
    baseline = next((row for row in db.earlier_completed_scans(scan_id)
                     if same_network(row['target'], scan['target'])
                     and comparable(ScanOptions(**json.loads(row['options'])), options)), None)
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


def _why_cves_are_not_compared(baseline: ScanOptions, current: ScanOptions) -> str | None:
    if not current.cve_lookup:
        return "These scans didn't look up CVEs."
    if not (baseline.cve_lookup_complete and current.cve_lookup_complete):
        return "A CVE lookup failed in this scan or the one before, so CVEs weren't compared."
    return None


def _not_comparable(scan_id: int, reason: str) -> dict[str, Any]:
    return {'scan_id': scan_id, 'comparable': False, 'reason': reason, 'baseline': None,
            'cves_compared': False, 'cves_reason': None, 'changes': None}

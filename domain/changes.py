"""What changed between a scan and the previous comparable scan of the same target (ADR-0013)."""
import ipaddress
from dataclasses import dataclass, field
from typing import Sequence

from domain.findings import Cve, Finding

_Key = tuple[str, str, int]


@dataclass(frozen=True)
class ScanOptions:
    """How a scan ran, which decides what it could find."""
    nmap_arguments: str
    cve_lookup: bool
    cve_lookup_complete: bool


@dataclass(frozen=True)
class ServiceChange:
    before: Finding
    after: Finding


@dataclass(frozen=True)
class CveChange:
    finding: Finding
    cves: tuple[Cve, ...]


@dataclass(frozen=True)
class HostNotSeen:
    """A host that had open ports before and none now: down, filtered or gone."""
    host: str
    findings: tuple[Finding, ...]


@dataclass
class ScanChanges:
    opened: list[Finding] = field(default_factory=list)
    closed: list[Finding] = field(default_factory=list)
    changed: list[ServiceChange] = field(default_factory=list)
    cves_added: list[CveChange] = field(default_factory=list)
    cves_removed: list[CveChange] = field(default_factory=list)
    hosts_not_seen: list[HostNotSeen] = field(default_factory=list)

    def any(self) -> bool:
        return any((self.opened, self.closed, self.changed, self.cves_added, self.cves_removed,
                    self.hosts_not_seen))


def comparable(a: ScanOptions, b: ScanOptions) -> bool:
    """True if two scans ran the same way, so their differences come from the hosts."""
    return a.nmap_arguments == b.nmap_arguments and a.cve_lookup == b.cve_lookup


def same_network(a: str, b: str) -> bool:
    """True if two targets name the same address or range, however they are spelled."""
    try:
        return ipaddress.ip_network(a, strict=False) == ipaddress.ip_network(b, strict=False)
    except ValueError:
        return False


def compare(previous: Sequence[Finding], current: Sequence[Finding], compare_cves: bool) -> ScanChanges:
    """Changes from previous to current, matched by host, protocol and port.

    compare_cves is False unless both scans completed their CVE lookups.
    """
    before = {_key(f): f for f in previous}
    after = {_key(f): f for f in current}
    hosts_now = {f.host for f in current}
    changes = ScanChanges()
    unseen: dict[str, list[Finding]] = {}
    for key in sorted(before.keys() - after.keys()):
        if key[0] in hosts_now:
            changes.closed.append(before[key])
        else:
            unseen.setdefault(key[0], []).append(before[key])
    changes.hosts_not_seen = [HostNotSeen(host, tuple(found)) for host, found in unseen.items()]
    changes.opened = [after[key] for key in sorted(after.keys() - before.keys())]
    for key in sorted(before.keys() & after.keys()):
        old, new = before[key], after[key]
        if _service(old) != _service(new):
            changes.changed.append(ServiceChange(old, new))
        if compare_cves:
            _compare_cves(old, new, changes)
    return changes


def _compare_cves(old: Finding, new: Finding, changes: ScanChanges) -> None:
    old_ids = {c.id for c in old.cves}
    new_ids = {c.id for c in new.cves}
    added = tuple(c for c in new.cves if c.id not in old_ids)
    if added:
        changes.cves_added.append(CveChange(new, added))
    # With the same product and version, a missing CVE means NVD's top matches shifted, not a fix.
    removed = tuple(c for c in old.cves if c.id not in new_ids)
    if removed and (old.product, old.version) != (new.product, new.version):
        changes.cves_removed.append(CveChange(new, removed))


def _key(f: Finding) -> _Key:
    return (f.host, f.protocol, f.port)


def _service(f: Finding) -> tuple[str, str, str]:
    return (f.service, f.product, f.version)

"""Scan findings: one service on one host, port and protocol (ADR-0003)."""
from dataclasses import asdict, dataclass
from typing import Literal, Sequence

Protocol = Literal["tcp", "udp"]


@dataclass(frozen=True)
class Cve:
    id: str
    score: float | None
    severity: str
    description: str


@dataclass(frozen=True)
class Finding:
    host: str
    port: int
    protocol: Protocol
    service: str
    product: str
    version: str
    cves: tuple[Cve, ...] = ()


def findings_to_json(findings: Sequence[Finding]) -> list[dict[str, object]]:
    """Plain, JSON-serializable form used for reports, storage and the API."""
    return [{**asdict(f), "cves": [asdict(c) for c in f.cves]} for f in findings]

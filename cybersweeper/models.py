# Data model used throughout Cyber Sweeper.
#
# The scanner modules produce these plain dataclasses; the storage and report
# layers consume them. Keeping the model independent from SQLite and from the
# user interfaces makes each layer easy to unit-test in isolation.

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "UNKNOWN": 0}


# Map a CVSS v3 base score to its qualitative severity.
def severity_from_cvss(score: Optional[float]) -> str:
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "INFO"


# A potential weakness associated with a service on a host.
@dataclass
class Vulnerability:
    cve_id: str  # e.g. CVE-2023-38408, or CS-RULE-xxx for built-in heuristics
    summary: str
    severity: str = "UNKNOWN"
    cvss_score: Optional[float] = None
    recommendation: str = ""
    source: str = "nvd"  # "nvd" or "rule"
    published: str = ""
    url: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# A single TCP/UDP port observed on a host.
@dataclass
class Port:
    number: int
    protocol: str = "tcp"
    state: str = "open"  # open / closed / filtered
    service: str = ""  # e.g. ssh, http
    product: str = ""  # e.g. OpenSSH
    version: str = ""  # e.g. 8.9p1
    banner: str = ""
    vulnerabilities: list[Vulnerability] = field(default_factory=list)

    @property
    def is_open(self) -> bool:
        return self.state == "open"

    # Human friendly product version string, fallback to service name.
    @property
    def service_label(self) -> str:
        parts = [p for p in (self.product, self.version) if p]
        return " ".join(parts) if parts else self.service or "unknown"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["service_label"] = self.service_label
        return d


# A network host and everything learned about it.
@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    is_up: bool = True
    discovery_method: str = ""
    ports: list[Port] = field(default_factory=list)

    @property
    def open_ports(self) -> list[Port]:
        return [p for p in self.ports if p.is_open]

    @property
    def vulnerabilities(self) -> list[Vulnerability]:
        return [v for p in self.ports for v in p.vulnerabilities]

    @property
    def max_severity(self) -> str:
        best = "INFO"
        for v in self.vulnerabilities:
            if SEVERITY_ORDER.get(v.severity, 0) > SEVERITY_ORDER.get(best, 0):
                best = v.severity
        return best if self.vulnerabilities else ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "os_guess": self.os_guess,
            "is_up": self.is_up,
            "discovery_method": self.discovery_method,
            "ports": [p.to_dict() for p in self.ports],
        }


# User-selected options for one scan run.
@dataclass
class ScanOptions:
    target: str
    ports: str = "top100"
    method: str = "auto"  # auto / socket / nmap
    discover: bool = True
    discovery_method: str = "auto"  # auto / ping / tcp / arp
    service_detection: bool = True
    cve_lookup: bool = False
    timeout: float = 1.0
    threads: int = 100
    max_hosts: int = 4096
    skip_discovery_for_single: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# The complete outcome of a scan.
@dataclass
class ScanResult:
    options: ScanOptions
    started_at: datetime = field(default_factory=datetime.now)
    finished_at: Optional[datetime] = None
    hosts: list[Host] = field(default_factory=list)
    engine: str = ""  # socket / nmap
    scan_id: Optional[int] = None  # populated once saved to the database
    notes: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        end = self.finished_at or datetime.now()
        return (end - self.started_at).total_seconds()

    @property
    def live_hosts(self) -> list[Host]:
        return [h for h in self.hosts if h.is_up]

    @property
    def total_open_ports(self) -> int:
        return sum(len(h.open_ports) for h in self.hosts)

    @property
    def total_vulnerabilities(self) -> int:
        return sum(len(h.vulnerabilities) for h in self.hosts)

    def to_dict(self) -> dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "options": self.options.to_dict(),
            "engine": self.engine,
            "started_at": self.started_at.isoformat(timespec="seconds"),
            "finished_at": self.finished_at.isoformat(timespec="seconds") if self.finished_at else None,
            "duration_seconds": round(self.duration, 2),
            "notes": list(self.notes),
            "hosts": [h.to_dict() for h in self.hosts],
        }

"""Persistence: SQLite database plus CSV / JSON export.

Schema (one row per entity, foreign keys cascade on delete)::

    scans           one row per scan run
    hosts           hosts seen in a scan
    ports           ports observed on a host
    vulnerabilities findings attached to a port
"""

from __future__ import annotations

import csv
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from cybersweep import config
from cybersweep.models import Host, Port, ScanOptions, ScanResult, Vulnerability

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    target       TEXT NOT NULL,
    ports_spec   TEXT NOT NULL,
    engine       TEXT NOT NULL,
    options_json TEXT NOT NULL,
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    duration     REAL,
    notes        TEXT
);
CREATE TABLE IF NOT EXISTS hosts (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id          INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    ip               TEXT NOT NULL,
    hostname         TEXT,
    mac              TEXT,
    vendor           TEXT,
    os_guess         TEXT,
    is_up            INTEGER NOT NULL DEFAULT 1,
    discovery_method TEXT
);
CREATE TABLE IF NOT EXISTS ports (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id   INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    number    INTEGER NOT NULL,
    protocol  TEXT NOT NULL DEFAULT 'tcp',
    state     TEXT NOT NULL,
    service   TEXT,
    product   TEXT,
    version   TEXT,
    banner    TEXT
);
CREATE TABLE IF NOT EXISTS vulnerabilities (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    port_id        INTEGER NOT NULL REFERENCES ports(id) ON DELETE CASCADE,
    cve_id         TEXT NOT NULL,
    summary        TEXT,
    severity       TEXT,
    cvss_score     REAL,
    recommendation TEXT,
    source         TEXT,
    published      TEXT,
    url            TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_scan ON hosts(scan_id);
CREATE INDEX IF NOT EXISTS idx_ports_host ON ports(host_id);
CREATE INDEX IF NOT EXISTS idx_vulns_port ON vulnerabilities(port_id);
"""


class Database:
    """Thin wrapper over ``sqlite3`` for saving and loading scan results."""

    def __init__(self, path: Optional[Path | str] = None) -> None:
        self.path = str(path) if path else str(config.default_db_path())
        self.conn = sqlite3.connect(self.path)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self.conn.executescript(SCHEMA)

    # -- context manager --------------------------------------------------

    def __enter__(self) -> Database:
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    # -- writing ----------------------------------------------------------

    def save_scan(self, result: ScanResult) -> int:
        """Persist a ScanResult and return its new ``scan_id``."""
        cur = self.conn.cursor()
        cur.execute(
            "INSERT INTO scans (target, ports_spec, engine, options_json, started_at, "
            "finished_at, duration, notes) VALUES (?,?,?,?,?,?,?,?)",
            (
                result.options.target, result.options.ports, result.engine,
                json.dumps(result.options.to_dict()),
                result.started_at.isoformat(timespec="seconds"),
                result.finished_at.isoformat(timespec="seconds") if result.finished_at else None,
                round(result.duration, 2), "\n".join(result.notes),
            ),
        )
        scan_id = cur.lastrowid
        for host in result.hosts:
            cur.execute(
                "INSERT INTO hosts (scan_id, ip, hostname, mac, vendor, os_guess, is_up, "
                "discovery_method) VALUES (?,?,?,?,?,?,?,?)",
                (scan_id, host.ip, host.hostname, host.mac, host.vendor, host.os_guess,
                 int(host.is_up), host.discovery_method),
            )
            host_id = cur.lastrowid
            for port in host.ports:
                cur.execute(
                    "INSERT INTO ports (host_id, number, protocol, state, service, product, "
                    "version, banner) VALUES (?,?,?,?,?,?,?,?)",
                    (host_id, port.number, port.protocol, port.state, port.service,
                     port.product, port.version, port.banner),
                )
                port_id = cur.lastrowid
                for v in port.vulnerabilities:
                    cur.execute(
                        "INSERT INTO vulnerabilities (port_id, cve_id, summary, severity, "
                        "cvss_score, recommendation, source, published, url) "
                        "VALUES (?,?,?,?,?,?,?,?,?)",
                        (port_id, v.cve_id, v.summary, v.severity, v.cvss_score,
                         v.recommendation, v.source, v.published, v.url),
                    )
        self.conn.commit()
        result.scan_id = scan_id
        return scan_id

    def delete_scan(self, scan_id: int) -> bool:
        cur = self.conn.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        self.conn.commit()
        return cur.rowcount > 0

    # -- reading ----------------------------------------------------------

    def list_scans(self, limit: int = 50) -> list[dict[str, Any]]:
        rows = self.conn.execute(
            "SELECT s.*, "
            " (SELECT COUNT(*) FROM hosts h WHERE h.scan_id = s.id AND h.is_up = 1) AS hosts_up, "
            " (SELECT COUNT(*) FROM ports p JOIN hosts h ON p.host_id = h.id "
            "   WHERE h.scan_id = s.id AND p.state = 'open') AS open_ports, "
            " (SELECT COUNT(*) FROM vulnerabilities v JOIN ports p ON v.port_id = p.id "
            "   JOIN hosts h ON p.host_id = h.id WHERE h.scan_id = s.id) AS vulns "
            "FROM scans s ORDER BY s.id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_scan_id(self) -> Optional[int]:
        row = self.conn.execute("SELECT MAX(id) AS id FROM scans").fetchone()
        return row["id"] if row and row["id"] is not None else None

    def load_scan(self, scan_id: int) -> Optional[ScanResult]:
        srow = self.conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if not srow:
            return None
        options = ScanOptions(**json.loads(srow["options_json"]))
        result = ScanResult(
            options=options, engine=srow["engine"],
            started_at=datetime.fromisoformat(srow["started_at"]),
            finished_at=datetime.fromisoformat(srow["finished_at"]) if srow["finished_at"] else None,
            scan_id=scan_id, notes=[n for n in (srow["notes"] or "").split("\n") if n],
        )
        for hrow in self.conn.execute("SELECT * FROM hosts WHERE scan_id = ? ORDER BY id", (scan_id,)):
            host = Host(ip=hrow["ip"], hostname=hrow["hostname"] or "", mac=hrow["mac"] or "",
                        vendor=hrow["vendor"] or "", os_guess=hrow["os_guess"] or "",
                        is_up=bool(hrow["is_up"]), discovery_method=hrow["discovery_method"] or "")
            for prow in self.conn.execute(
                    "SELECT * FROM ports WHERE host_id = ? ORDER BY number", (hrow["id"],)):
                port = Port(number=prow["number"], protocol=prow["protocol"], state=prow["state"],
                            service=prow["service"] or "", product=prow["product"] or "",
                            version=prow["version"] or "", banner=prow["banner"] or "")
                for vrow in self.conn.execute(
                        "SELECT * FROM vulnerabilities WHERE port_id = ? ORDER BY cvss_score DESC",
                        (prow["id"],)):
                    port.vulnerabilities.append(Vulnerability(
                        cve_id=vrow["cve_id"], summary=vrow["summary"] or "",
                        severity=vrow["severity"] or "UNKNOWN", cvss_score=vrow["cvss_score"],
                        recommendation=vrow["recommendation"] or "", source=vrow["source"] or "",
                        published=vrow["published"] or "", url=vrow["url"] or ""))
                host.ports.append(port)
            result.hosts.append(host)
        return result


# --------------------------------------------------------------------------- #
# Flat exports
# --------------------------------------------------------------------------- #

CSV_COLUMNS = ["scan_id", "ip", "hostname", "mac", "vendor", "port", "protocol", "state",
               "service", "product", "version", "banner", "finding_id", "severity",
               "cvss_score", "summary", "recommendation"]


def flatten(result: ScanResult, open_only: bool = True) -> list[dict[str, Any]]:
    """Return one flat row per (host, port, finding) combination.

    Hosts without ports and ports without findings still produce a row so the
    export never silently drops information.
    """
    rows: list[dict[str, Any]] = []
    for host in result.hosts:
        ports = host.open_ports if open_only else host.ports
        base = {"scan_id": result.scan_id, "ip": host.ip, "hostname": host.hostname,
                "mac": host.mac, "vendor": host.vendor}
        if not ports:
            rows.append({**base, "port": "", "protocol": "", "state": "up" if host.is_up else "down",
                         "service": "", "product": "", "version": "", "banner": "",
                         "finding_id": "", "severity": "", "cvss_score": "", "summary": "",
                         "recommendation": ""})
            continue
        for port in ports:
            prow = {**base, "port": port.number, "protocol": port.protocol, "state": port.state,
                    "service": port.service, "product": port.product, "version": port.version,
                    "banner": port.banner}
            if not port.vulnerabilities:
                rows.append({**prow, "finding_id": "", "severity": "", "cvss_score": "",
                             "summary": "", "recommendation": ""})
            for v in port.vulnerabilities:
                rows.append({**prow, "finding_id": v.cve_id, "severity": v.severity,
                             "cvss_score": v.cvss_score if v.cvss_score is not None else "",
                             "summary": v.summary, "recommendation": v.recommendation})
    return rows


def export_csv(result: ScanResult, path: Path | str, open_only: bool = True) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(flatten(result, open_only=open_only))
    return path


def export_json(result: ScanResult, path: Path | str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(result.to_dict(), indent=2), encoding="utf-8")
    return path

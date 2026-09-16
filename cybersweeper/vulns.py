# Vulnerability lookup.
#
# Two complementary sources are used:
#
# 1. Built-in rules (always available, offline) - configuration weaknesses
#    that are risky regardless of software version: clear-text protocols
#    (Telnet, FTP), management services exposed on the network (RDP, SMB, VNC,
#    databases without authentication) and similar. Each rule carries a
#    severity and a remediation recommendation.
# 2. NVD CVE database (online) - the National Vulnerability Database REST
#    API 2.0 is queried by *product + version* keyword for every identified
#    service. Results are cached on disk (JSON) so repeated scans do not hit the
#    API again and so the tool still works offline for previously seen services.
#
# An optional API key (NVD_API_KEY environment variable) lifts the public
# rate limit from 5 to 50 requests per 30 seconds.

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable, Optional

from cybersweeper import config
from cybersweeper.models import Host, Port, Vulnerability, severity_from_cvss
from cybersweeper.utils import truncate_words

log = logging.getLogger("cybersweeper.vulns")


# --------------------------------------------------------------------------- #
# Built-in heuristic rules
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    rule_id: str
    match_services: frozenset  # service names
    match_ports: frozenset  # port numbers (either may be empty)
    severity: str
    summary: str
    recommendation: str

    def matches(self, port: Port) -> bool:
        if not port.is_open:
            return False
        svc = (port.service or "").lower()
        return svc in self.match_services or port.number in self.match_ports


def _rule(rule_id, services, ports, severity, summary, recommendation) -> Rule:
    return Rule(rule_id, frozenset(services), frozenset(ports), severity, summary, recommendation)


BUILTIN_RULES: list[Rule] = [
    _rule("CS-RULE-001", {"telnet"}, {23}, "HIGH",
          "Telnet transmits credentials and session data in clear text.",
          "Disable Telnet and use SSH for remote administration."),
    _rule("CS-RULE-002", {"ftp", "ftp-alt"}, {21, 2121}, "MEDIUM",
          "FTP sends usernames and passwords unencrypted.",
          "Replace FTP with SFTP/FTPS, or restrict it to trusted networks."),
    _rule("CS-RULE-003", {"ms-wbt-server", "rdp"}, {3389}, "HIGH",
          "Remote Desktop (RDP) is reachable; RDP is a frequent brute-force and exploit target.",
          "Restrict RDP to a VPN or firewall allow-list, enforce NLA and MFA, keep Windows patched."),
    _rule("CS-RULE-004", {"microsoft-ds", "netbios-ssn"}, {445, 139}, "HIGH",
          "SMB file sharing is exposed; SMB has a history of wormable vulnerabilities (e.g. EternalBlue).",
          "Block ports 139/445 at the network boundary, disable SMBv1, and patch the host."),
    _rule("CS-RULE-005", {"vnc", "vnc-1"}, {5900, 5901}, "HIGH",
          "VNC remote desktop is exposed; many VNC deployments use weak or no passwords.",
          "Tunnel VNC over SSH/VPN and enforce strong authentication."),
    _rule("CS-RULE-006", {"mysql", "postgresql", "ms-sql-s", "oracle"}, {3306, 5432, 1433, 1521}, "MEDIUM",
          "A database service accepts network connections.",
          "Bind the database to localhost or an internal interface and firewall the port."),
    _rule("CS-RULE-007", {"redis"}, {6379}, "CRITICAL",
          "Redis is exposed; Redis has no authentication by default and can be abused for remote code execution.",
          "Bind Redis to 127.0.0.1, enable 'requirepass' and protected mode."),
    _rule("CS-RULE-008", {"mongodb"}, {27017, 27018}, "CRITICAL",
          "MongoDB is exposed; unauthenticated MongoDB instances are routinely ransomed.",
          "Enable authentication, bind to internal interfaces, firewall the port."),
    _rule("CS-RULE-009", {"elasticsearch"}, {9200, 9300}, "HIGH",
          "Elasticsearch REST API is exposed and typically has no authentication.",
          "Enable X-Pack security or restrict access to the API with a firewall."),
    _rule("CS-RULE-010", {"memcached"}, {11211}, "HIGH",
          "Memcached is exposed; it can leak cached data and be used for DDoS amplification.",
          "Bind Memcached to localhost and disable UDP."),
    _rule("CS-RULE-011", {"snmp"}, {161}, "MEDIUM",
          "SNMP is exposed; SNMPv1/v2c use community strings sent in clear text.",
          "Use SNMPv3 with authentication and encryption, change default community strings."),
    _rule("CS-RULE-012", {"docker"}, {2375}, "CRITICAL",
          "Unencrypted Docker daemon API is exposed - equivalent to root access on the host.",
          "Never expose port 2375; use TLS on 2376 with client certificates or a local socket only."),
    _rule("CS-RULE-013", {"rpcbind", "nfs"}, {111, 2049}, "MEDIUM",
          "RPC/NFS services are reachable and may expose file systems.",
          "Restrict exports to trusted hosts and firewall the ports."),
    _rule("CS-RULE-014", {"x11"}, {6000}, "HIGH",
          "X11 display server is listening on the network.",
          "Disable TCP listening for X11 (-nolisten tcp) and use SSH X forwarding."),
    _rule("CS-RULE-015", {"pop3", "imap", "smtp"}, {110, 143, 25}, "LOW",
          "Mail protocol without TLS on its default port; credentials may be sent in clear text.",
          "Require STARTTLS or move to the TLS variants (995/993/465)."),
    _rule("CS-RULE-016", {"http", "http-alt", "http-proxy"}, set(), "INFO",
          "Web service over plain HTTP.",
          "Serve content over HTTPS and redirect HTTP to HTTPS."),
    _rule("CS-RULE-017", {"upnp"}, {1900, 5000}, "MEDIUM",
          "UPnP is exposed; it can be abused to open firewall pinholes.",
          "Disable UPnP unless it is required."),
    _rule("CS-RULE-018", {"winrm", "winrm-https"}, {5985, 5986}, "MEDIUM",
          "Windows Remote Management is reachable.",
          "Restrict WinRM to management networks and require HTTPS + Kerberos."),
    _rule("CS-RULE-019", {"kubernetes-api"}, {6443}, "HIGH",
          "Kubernetes API server is exposed.",
          "Restrict API access to trusted networks and enforce RBAC."),
    _rule("CS-RULE-020", {"webmin"}, {10000}, "MEDIUM",
          "Webmin administration panel is exposed.",
          "Restrict Webmin to an admin network and keep it updated."),
]


# Return the built-in findings that apply to *port*.
def rule_findings(port: Port) -> list[Vulnerability]:
    findings = []
    for rule in BUILTIN_RULES:
        if rule.matches(port):
            findings.append(Vulnerability(
                cve_id=rule.rule_id, summary=rule.summary, severity=rule.severity,
                cvss_score=None, recommendation=rule.recommendation, source="rule",
            ))
    return findings


# --------------------------------------------------------------------------- #
# NVD lookups with disk cache
# --------------------------------------------------------------------------- #

GENERIC_PRODUCTS = {"", "http server", "ftp server", "smtp server", "pop3 server",
                    "imap server", "tls web server", "unknown", "rtsp server", "sip server",
                    "smb", "telnet", "microsoft rdp"}


# Tiny JSON-file cache: {query: {"fetched": iso, "items": [...]}}.
class CVECache:
    def __init__(self, path: Optional[Path] = None, ttl_days: int = config.CVE_CACHE_TTL_DAYS):
        self.path = Path(path) if path else config.default_cache_path()
        self.ttl = timedelta(days=ttl_days)
        self._data: dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        try:
            self._data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._data = {}

    def save(self) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self._data, indent=1), encoding="utf-8")
        except OSError as exc:  # pragma: no cover
            log.debug("cannot write CVE cache: %s", exc)

    def get(self, key: str) -> Optional[list[dict]]:
        entry = self._data.get(key)
        if not entry:
            return None
        try:
            fetched = datetime.fromisoformat(entry["fetched"])
        except (KeyError, ValueError):
            return None
        if datetime.now() - fetched > self.ttl:
            return None
        return entry.get("items", [])

    def put(self, key: str, items: list[dict]) -> None:
        self._data[key] = {"fetched": datetime.now().isoformat(timespec="seconds"), "items": items}


# True when NVD has withdrawn this CVE.
#
# A rejected entry is not a vulnerability. It keeps its CVE number and stays in
# the database, its description rewritten to start "Rejected reason: ...", and a
# keyword search still returns it. Reporting one is worse than reporting
# nothing: it has no CVSS score, so it lands in the register with no severity,
# and the standard "update to a patched version" advice is meaningless because
# there is nothing to patch. Drop these at the source.
def is_rejected(cve: dict, summary: str) -> bool:
    if str(cve.get("vulnStatus", "")).strip().lower() == "rejected":
        return True
    return summary.lstrip().lower().startswith("rejected reason")


# Convert an NVD API 2.0 JSON payload into Vulnerability objects.
def parse_nvd_response(payload: dict) -> list[Vulnerability]:
    vulns: list[Vulnerability] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            continue
        descriptions = cve.get("descriptions", [])
        summary = next((d["value"] for d in descriptions if d.get("lang") == "en"),
                       descriptions[0]["value"] if descriptions else "")
        if is_rejected(cve, summary):
            continue
        score: Optional[float] = None
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                score = metrics[key][0]["cvssData"].get("baseScore")
                break
        vulns.append(Vulnerability(
            cve_id=cve_id, summary=truncate_words(summary, 500), severity=severity_from_cvss(score),
            cvss_score=score, source="nvd", published=cve.get("published", "")[:10],
            url=f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            recommendation="Update the affected software to a patched version; see the NVD entry.",
        ))
    vulns.sort(key=lambda v: (v.cvss_score or 0), reverse=True)
    return vulns


# Minimal client for the NVD CVE API 2.0 with rate limiting and caching.
class NVDClient:
    def __init__(self, api_key: Optional[str] = None, cache: Optional[CVECache] = None,
                 session=None, max_results: int = config.NVD_RESULTS_PER_QUERY,
                 offline: bool = False) -> None:
        self.api_key = api_key if api_key is not None else os.environ.get(config.NVD_API_KEY_ENV)
        self.cache = cache or CVECache()
        self.max_results = max_results
        self.offline = offline
        self._session = session
        self._last_request = 0.0
        self.errors: list[str] = []

    @property
    def session(self):
        if self._session is None:
            import requests

            self._session = requests.Session()
        return self._session

    def _throttle(self) -> None:
        delay = config.NVD_DELAY_WITH_KEY if self.api_key else config.NVD_DELAY_NO_KEY
        wait = delay - (time.monotonic() - self._last_request)
        if wait > 0:
            time.sleep(wait)
        self._last_request = time.monotonic()

    @staticmethod
    def make_query(product: str, version: str) -> str:
        import re

        product = product.strip()
        # "8.9p1 Ubuntu-3ubuntu0.6" -> "8.9"; NVD keyword search works best with
        # the plain numeric version.
        m = re.match(r"\s*v?(\d+(?:\.\d+)*)", version or "")
        version = m.group(1) if m else ""
        return f"{product} {version}".strip()

    # Look up CVEs for a product/version, using the cache when possible.
    def search(self, product: str, version: str) -> list[Vulnerability]:
        if not product or product.lower() in GENERIC_PRODUCTS:
            return []
        query = self.make_query(product, version)
        cached = self.cache.get(query)
        if cached is not None:
            return [Vulnerability(**v) for v in cached]
        if self.offline:
            return []

        params: dict[str, Any] = {"keywordSearch": query, "resultsPerPage": self.max_results}
        headers = {"User-Agent": "CyberSweeper/1.0"}  # HTTP product tokens cannot contain spaces
        if self.api_key:
            headers["apiKey"] = self.api_key
        self._throttle()
        try:
            resp = self.session.get(config.NVD_API_URL, params=params, headers=headers,
                                    timeout=config.NVD_TIMEOUT)
            if resp.status_code == 403:
                raise RuntimeError("NVD rate limit hit (HTTP 403); set NVD_API_KEY or retry later")
            resp.raise_for_status()
            vulns = parse_nvd_response(resp.json())
        except Exception as exc:  # network errors, JSON errors, HTTP errors
            msg = f"NVD lookup failed for '{query}': {exc}"
            log.warning(msg)
            self.errors.append(msg)
            return []
        self.cache.put(query, [v.to_dict() for v in vulns])
        self.cache.save()
        return vulns


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #


# Attach vulnerabilities to every open port of *host*.
#
# *client* may be None to skip online CVE lookups.
def assess_host(host: Host, client: Optional[NVDClient] = None, use_rules: bool = True,
                progress: Optional[Callable[[str], None]] = None) -> Host:
    for port in host.open_ports:
        found: list[Vulnerability] = []
        if use_rules:
            found.extend(rule_findings(port))
        if client is not None and port.product:
            if progress:
                progress(f"CVE lookup {host.ip}:{port.number} {port.service_label}")
            found.extend(client.search(port.product, port.version))
        # de-duplicate by id, keep highest severity first
        seen: set[str] = set()
        unique = []
        for v in found:
            if v.cve_id not in seen:
                seen.add(v.cve_id)
                unique.append(v)
        port.vulnerabilities = unique
    return host

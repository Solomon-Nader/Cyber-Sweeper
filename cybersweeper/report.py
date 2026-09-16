# Report generation: filtering, sorting and rendering scan results as plain
# text (for the console), Markdown or a self-contained HTML page.

from __future__ import annotations

import html
from dataclasses import dataclass, field
from typing import Optional

from cybersweeper import __version__
from cybersweeper.models import SEVERITY_ORDER, Host, Port, ScanResult
from cybersweeper.utils import human_duration

# --------------------------------------------------------------------------- #
# Filtering
# --------------------------------------------------------------------------- #


# Criteria used to narrow down what a report shows.
@dataclass
class ReportFilter:
    hosts: list[str] = field(default_factory=list)  # IP substrings / hostnames
    ports: list[int] = field(default_factory=list)
    services: list[str] = field(default_factory=list)  # substrings, case-insensitive
    states: list[str] = field(default_factory=lambda: ["open"])
    min_severity: Optional[str] = None  # only show ports with a finding >= this
    only_vulnerable: bool = False
    live_only: bool = True
    sort_by: str = "ip"  # ip / open_ports / severity

    def port_matches(self, port: Port) -> bool:
        if self.states and port.state not in self.states:
            return False
        if self.ports and port.number not in self.ports:
            return False
        if self.services:
            hay = f"{port.service} {port.product} {port.version}".lower()
            if not any(s.lower() in hay for s in self.services):
                return False
        if self.only_vulnerable and not port.vulnerabilities:
            return False
        if self.min_severity:
            threshold = SEVERITY_ORDER.get(self.min_severity.upper(), 0)
            if not any(SEVERITY_ORDER.get(v.severity, 0) >= threshold for v in port.vulnerabilities):
                return False
        return True

    def host_matches(self, host: Host) -> bool:
        if self.live_only and not host.is_up:
            return False
        if self.hosts:
            hay = f"{host.ip} {host.hostname}".lower()
            if not any(h.lower() in hay for h in self.hosts):
                return False
        return True

    # Return filtered *copies* of hosts (the original result is untouched).
    def apply(self, result: ScanResult) -> list[Host]:
        out: list[Host] = []
        for host in result.hosts:
            if not self.host_matches(host):
                continue
            ports = [p for p in host.ports if self.port_matches(p)]
            if (self.ports or self.services or self.only_vulnerable or self.min_severity) and not ports:
                continue
            clone = Host(ip=host.ip, hostname=host.hostname, mac=host.mac, vendor=host.vendor,
                         os_guess=host.os_guess, is_up=host.is_up,
                         discovery_method=host.discovery_method, ports=ports)
            out.append(clone)
        return self.sort(out)

    def sort(self, hosts: list[Host]) -> list[Host]:
        if self.sort_by == "open_ports":
            return sorted(hosts, key=lambda h: len(h.open_ports), reverse=True)
        if self.sort_by == "severity":
            return sorted(hosts, key=lambda h: SEVERITY_ORDER.get(h.max_severity, -1), reverse=True)
        return sorted(hosts, key=lambda h: tuple(int(o) if o.isdigit() else 0 for o in h.ip.split(".")))


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


# Render a simple ASCII table (no third-party dependency).
def _table(headers: list[str], rows: list[list[str]], max_width: int = 60) -> str:
    if not rows:
        return "  (none)"
    rows = [[str(c)[:max_width] for c in row] for row in rows]
    widths = [max(len(h), *(len(r[i]) for r in rows)) for i, h in enumerate(headers)]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    fmt = "|" + "|".join(f" {{:<{w}}} " for w in widths) + "|"
    lines = [sep, fmt.format(*headers), sep]
    lines += [fmt.format(*r) for r in rows]
    lines.append(sep)
    return "\n".join(lines)


def severity_summary(hosts: list[Host]) -> dict[str, int]:
    counts = dict.fromkeys(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"], 0)
    for h in hosts:
        for v in h.vulnerabilities:
            counts[v.severity if v.severity in counts else "UNKNOWN"] += 1
    return counts


def _meta_lines(result: ScanResult, hosts: list[Host]) -> list[str]:
    return [
        f"Target        : {result.options.target}",
        f"Ports         : {result.options.ports}",
        f"Engine        : {result.engine or 'n/a'}",
        f"Started       : {result.started_at:%Y-%m-%d %H:%M:%S}",
        f"Duration      : {human_duration(result.duration)}",
        f"Hosts shown   : {len(hosts)} (of {len(result.hosts)} scanned)",
        f"Open ports    : {sum(len(h.open_ports) for h in hosts)}",
        f"Findings      : {sum(len(h.vulnerabilities) for h in hosts)}",
    ]


# --------------------------------------------------------------------------- #
# Text
# --------------------------------------------------------------------------- #


def render_text(result: ScanResult, flt: Optional[ReportFilter] = None,
                show_findings: bool = True) -> str:
    flt = flt or ReportFilter()
    hosts = flt.apply(result)
    out: list[str] = []
    title = f"Cyber Sweeper report - scan #{result.scan_id}" if result.scan_id else "Cyber Sweeper report"
    out.append(title)
    out.append("=" * len(title))
    out.extend(_meta_lines(result, hosts))
    if result.notes:
        out.append("Notes         : " + "; ".join(result.notes))
    sev = severity_summary(hosts)
    out.append("Severity      : " + "  ".join(f"{k} {v}" for k, v in sev.items() if v))
    out.append("")

    if not hosts:
        out.append("No hosts match the current filter.")
        return "\n".join(out)

    for host in hosts:
        label = host.ip + (f" ({host.hostname})" if host.hostname else "")
        extra = " ".join(x for x in (host.mac, host.vendor and f"[{host.vendor}]", host.os_guess) if x)
        out.append(f"Host {label} {extra}".rstrip())
        out.append("-" * (5 + len(label)))
        rows = [[f"{p.number}/{p.protocol}", p.state, p.service, p.service_label if p.product else "",
                 p.banner, (p.vulnerabilities and max(p.vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 0)).severity) or ""]
                for p in host.ports]
        out.append(_table(["PORT", "STATE", "SERVICE", "PRODUCT/VERSION", "BANNER", "RISK"], rows))
        if show_findings:
            for p in host.ports:
                for v in p.vulnerabilities:
                    score = f" ({v.cvss_score})" if v.cvss_score is not None else ""
                    out.append(f"  [{v.severity}{score}] {p.number}/{p.protocol} {v.cve_id}: {v.summary}")
                    if v.recommendation:
                        out.append(f"      -> {v.recommendation}")
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# Markdown
# --------------------------------------------------------------------------- #


def render_markdown(result: ScanResult, flt: Optional[ReportFilter] = None) -> str:
    flt = flt or ReportFilter()
    hosts = flt.apply(result)
    out = [f"# Cyber Sweeper report{f' - scan #{result.scan_id}' if result.scan_id else ''}", ""]
    out += [f"- {line}" for line in _meta_lines(result, hosts)]
    out.append("")
    for host in hosts:
        out.append(f"## {host.ip}{f' ({host.hostname})' if host.hostname else ''}")
        out.append("")
        out.append("| Port | State | Service | Product / version | Risk |")
        out.append("|------|-------|---------|-------------------|------|")
        for p in host.ports:
            risk = max((v.severity for v in p.vulnerabilities), key=lambda s: SEVERITY_ORDER.get(s, 0), default="")
            out.append(f"| {p.number}/{p.protocol} | {p.state} | {p.service} | {p.service_label if p.product else ''} | {risk} |")
        findings = host.vulnerabilities
        if findings:
            out.append("")
            out.append("**Findings**")
            out.append("")
            for p in host.ports:
                for v in p.vulnerabilities:
                    out.append(f"- **{v.severity}** `{v.cve_id}` on {p.number}/{p.protocol}: {v.summary}"
                               + (f" _Recommendation: {v.recommendation}_" if v.recommendation else ""))
        out.append("")
    return "\n".join(out)


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #

_CSS = """
body{font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;margin:0;background:#f4f6f9;color:#1f2933}
header{background:#0b3d5c;color:#fff;padding:20px 32px}header h1{margin:0;font-size:24px}
header p{margin:4px 0 0;opacity:.85}main{padding:24px 32px;max-width:1200px;margin:auto}
.meta{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px;margin-bottom:24px}
.meta div{background:#fff;border-radius:8px;padding:12px 16px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
.meta b{display:block;font-size:12px;text-transform:uppercase;color:#627d98;letter-spacing:.04em}
.sev{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px}.sev span{padding:6px 12px;border-radius:999px;color:#fff;font-weight:600;font-size:13px}
.CRITICAL{background:#7f1d1d}.HIGH{background:#c2410c}.MEDIUM{background:#b45309}.LOW{background:#2563eb}.INFO{background:#4b5563}.UNKNOWN{background:#6b7280}
section{background:#fff;border-radius:8px;padding:16px 20px;margin-bottom:20px;box-shadow:0 1px 3px rgba(0,0,0,.08)}
h2{margin:0 0 8px;font-size:18px}h2 small{color:#627d98;font-weight:400;font-size:13px;margin-left:8px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #e5e9f0;vertical-align:top}
th{background:#f0f4f8;font-size:12px;text-transform:uppercase;color:#486581}td.mono{font-family:Consolas,monospace;font-size:12px;color:#486581}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;color:#fff;font-size:11px;font-weight:700}
ul.findings{margin:12px 0 0;padding-left:0;list-style:none}ul.findings li{padding:8px 10px;border-left:4px solid #ccc;background:#f9fafb;margin-bottom:6px;font-size:13px}
ul.findings li.CRITICAL{border-color:#7f1d1d;background:#fff}ul.findings li.HIGH{border-color:#c2410c;background:#fff}ul.findings li.MEDIUM{border-color:#b45309;background:#fff}
ul.findings li.LOW{border-color:#2563eb;background:#fff}ul.findings li.INFO{border-color:#4b5563;background:#fff}
.rec{color:#334e68;display:block;margin-top:4px}footer{text-align:center;color:#829ab1;font-size:12px;padding:20px}
"""


def render_html(result: ScanResult, flt: Optional[ReportFilter] = None) -> str:
    flt = flt or ReportFilter()
    hosts = flt.apply(result)
    e = html.escape
    sev = severity_summary(hosts)
    parts = [
        "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>",
        f"<title>Cyber Sweeper report {f'#{result.scan_id}' if result.scan_id else ''}</title>",
        f"<style>{_CSS}</style></head><body>",
        "<header><h1>Cyber Sweeper Network Inspection Report</h1>",
        f"<p>Target {e(result.options.target)} &middot; {result.started_at:%Y-%m-%d %H:%M} &middot; "
        f"engine {e(result.engine or 'n/a')}</p></header><main>",
        "<div class='meta'>",
    ]
    for line in _meta_lines(result, hosts):
        k, _, v = line.partition(":")
        parts.append(f"<div><b>{e(k.strip())}</b>{e(v.strip())}</div>")
    parts.append("</div><div class='sev'>")
    for k, v in sev.items():
        if v:
            parts.append(f"<span class='{k}'>{k} {v}</span>")
    if not any(sev.values()):
        parts.append("<span class='INFO'>No findings</span>")
    parts.append("</div>")

    if not hosts:
        parts.append("<section><p>No hosts match the current filter.</p></section>")

    for host in hosts:
        sub = " &middot; ".join(e(x) for x in (host.hostname, host.mac, host.vendor, host.os_guess) if x)
        parts.append(f"<section><h2>{e(host.ip)}<small>{sub}</small></h2>")
        parts.append("<table><thead><tr><th>Port</th><th>State</th><th>Service</th>"
                     "<th>Product / version</th><th>Banner</th><th>Risk</th></tr></thead><tbody>")
        for p in host.ports:
            risk = max((v.severity for v in p.vulnerabilities), key=lambda s: SEVERITY_ORDER.get(s, 0), default="")
            badge = f"<span class='badge {risk}'>{risk}</span>" if risk else ""
            parts.append(f"<tr><td>{p.number}/{e(p.protocol)}</td><td>{e(p.state)}</td><td>{e(p.service)}</td>"
                         f"<td>{e(p.service_label if p.product else '')}</td><td class='mono'>{e(p.banner)}</td><td>{badge}</td></tr>")
        parts.append("</tbody></table>")
        findings = [(p, v) for p in host.ports for v in p.vulnerabilities]
        if findings:
            findings.sort(key=lambda pv: SEVERITY_ORDER.get(pv[1].severity, 0), reverse=True)
            parts.append("<ul class='findings'>")
            for p, v in findings:
                link = f"<a href='{e(v.url)}' target='_blank'>{e(v.cve_id)}</a>" if v.url else e(v.cve_id)
                score = f" (CVSS {v.cvss_score})" if v.cvss_score is not None else ""
                parts.append(f"<li class='{v.severity}'><span class='badge {v.severity}'>{v.severity}</span>{score} "
                             f"<b>{link}</b> on port {p.number}: {e(v.summary)}"
                             + (f"<span class='rec'>Recommendation: {e(v.recommendation)}</span>" if v.recommendation else "")
                             + "</li>")
            parts.append("</ul>")
        parts.append("</section>")
    parts.append(f"</main><footer>Generated by Cyber Sweeper {__version__}. Scan only networks you are authorised to test.</footer></body></html>")
    return "".join(parts)


RENDERERS = {"text": render_text, "markdown": render_markdown, "md": render_markdown, "html": render_html}


def render(result: ScanResult, fmt: str = "text", flt: Optional[ReportFilter] = None) -> str:
    try:
        renderer = RENDERERS[fmt.lower()]
    except KeyError as exc:
        raise ValueError(f"unknown report format '{fmt}' (text, markdown, html)") from exc
    return renderer(result, flt)

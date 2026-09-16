import zipfile

import pytest

from cybersweeper import cli, techreport
from cybersweeper.models import ScanOptions, ScanResult
from cybersweeper.report import ReportFilter


def test_build_content_summary_and_ordering(sample_result):
    sample_result.notes.insert(0, "target auto-detected: Connected to Wi-Fi 'Lab' via wlan0 - 192.168.1.5/24 (192.168.1.0/24, 254 hosts)")
    sample_result.options.cve_lookup = True
    c = techreport.build_content(sample_result, organisation="Acme")
    assert c.overall_risk == "CRITICAL"
    assert c.severity_counts["CRITICAL"] == 1 and c.severity_counts["HIGH"] == 1
    assert c.meta["Organisation"] == "Acme"
    assert "Wi-Fi 'Lab'" in c.meta["Network context"]
    assert c.subtitle.startswith("Connected to Wi-Fi 'Lab'")
    assert "2 hosts were found live" in c.summary_paragraphs[0]
    assert "National Vulnerability Database" in c.summary_paragraphs[2]
    # register sorted by severity, critical first
    assert [f["id"] for f in c.findings_rows] == ["CVE-2023-38408", "CS-RULE-001"]
    assert c.top_findings[0]["severity"] == "CRITICAL"
    # remediation: one action per unique recommendation, prioritised
    assert [e["priority"] for e in c.remediation] == [1, 2]
    assert c.remediation[0]["action"] == "Upgrade OpenSSH" and c.remediation[0]["targets"] == ["192.168.1.10:22"]
    # inventory only live hosts, sorted by IP
    assert [row[0] for row in c.inventory_rows] == ["192.168.1.2", "192.168.1.10"]
    assert c.inventory_rows[1][4] == "CRITICAL" and c.inventory_rows[0][4] == "none confirmed"
    # per-host sections carry port rows (closed port hidden by default filter)
    sec = next(s for s in c.hosts if s.host.ip == "192.168.1.10")
    assert [r[0] for r in sec.port_rows] == ["22/tcp", "23/tcp"]
    assert len(sec.findings) == 2


def test_build_content_no_findings_and_offline_wording():
    result = ScanResult(options=ScanOptions(target="10.0.0.1", cve_lookup=False), engine="socket")
    result.finished_at = result.started_at
    c = techreport.build_content(result)
    assert c.overall_risk == "NONE"
    assert "No security findings" in c.summary_paragraphs[1]
    assert "was not enabled" in c.summary_paragraphs[2]
    assert c.meta["Host discovery"] == "not needed (single host)"
    assert c.remediation == [] and c.findings_rows == []


def test_build_content_respects_filter(sample_result):
    c = techreport.build_content(sample_result, ReportFilter(min_severity="CRITICAL"))
    assert [f["id"] for f in c.findings_rows] == ["CVE-2023-38408"]
    assert len(c.hosts) == 1


def test_write_pdf(tmp_path, sample_result):
    pytest.importorskip("reportlab")
    out = techreport.write_pdf(sample_result, tmp_path / "out" / "r.pdf", organisation="Acme")
    data = out.read_bytes()
    assert data.startswith(b"%PDF") and len(data) > 5000
    assert b"/Title (Network Security Assessment Report)" in data or b"Network Security Assessment Report" in data


def test_write_docx_contains_sections(tmp_path, sample_result):
    docx = pytest.importorskip("docx")
    out = techreport.write_docx(sample_result, tmp_path / "r.docx", title="Lab Report")
    assert zipfile.is_zipfile(out)
    d = docx.Document(str(out))
    text = "\n".join(p.text for p in d.paragraphs)
    assert "Lab Report" in text
    for heading in ("1. Executive summary", "2. Scope and methodology", "3. Host inventory",
                    "4. Detailed results per host", "5. Findings register", "6. Remediation plan",
                    "Appendix B - Glossary"):
        assert heading in text
    cells = "\n".join(c.text for t in d.tables for row in t.rows for c in row.cells)
    assert "CVE-2023-38408" in cells and "Upgrade OpenSSH" in cells and "192.168.1.10" in cells


def test_write_dispatch_unknown_format(tmp_path, sample_result):
    with pytest.raises(ValueError):
        techreport.write(sample_result, "odt", tmp_path / "x.odt")


def test_cli_report_pdf_and_docx(tmp_path, sample_result):
    pytest.importorskip("reportlab")
    pytest.importorskip("docx")
    from cybersweeper import storage

    db = tmp_path / "t.db"
    with storage.Database(db) as d:
        d.save_scan(sample_result)
    pdf = tmp_path / "rep.pdf"
    assert cli.main(["--db", str(db), "report", "1", "-f", "pdf", "-o", str(pdf), "--org", "Acme"]) == 0
    assert pdf.exists() and pdf.read_bytes().startswith(b"%PDF")
    assert cli.main(["--db", str(db), "report", "-f", "docx", "-o", str(tmp_path / "rep.docx")]) == 0
    assert (tmp_path / "rep.docx").exists()


def test_cli_scan_exports_pdf(tmp_path, ssh_server, monkeypatch):
    pytest.importorskip("reportlab")
    from cybersweeper import portscan

    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    pdf = tmp_path / "scan.pdf"
    rc = cli.main(["--no-banner", "-q", "scan", "127.0.0.1", "-p", str(ssh_server.port), "--no-save",
                   "--pdf", str(pdf), "--title", "Loopback check"])
    assert rc == 0 and pdf.exists()
    assert b"Loopback check" in pdf.read_bytes()


# --------------------------------------------------------------------------- #
# Honest reporting (2.1.0)
# --------------------------------------------------------------------------- #


def _host_with(*ports):
    from cybersweeper.models import Host

    h = Host(ip="10.0.0.1", hostname="router")
    h.ports.extend(ports)
    return h


def _port(number, product="Samba smbd", version="3.X - 4.X", vulns=()):
    from cybersweeper.models import Port

    p = Port(number=number, state="open", service="netbios-ssn", product=product, version=version)
    p.vulnerabilities.extend(vulns)
    return p


def _cve(cve_id, severity, score, source="nvd"):
    from cybersweeper.models import Vulnerability

    return Vulnerability(cve_id=cve_id, summary="s", severity=severity, cvss_score=score,
                         source=source, recommendation="Patch it.")


def _result(hosts, **opts):
    from cybersweeper.models import ScanOptions, ScanResult

    r = ScanResult(options=ScanOptions(target="10.0.0.0/24", cve_lookup=True, **opts), engine="nmap")
    r.finished_at = r.started_at
    r.hosts.extend(hosts)
    r.notes.append("discovery via arp/nmap: 2/254 hosts up")
    return r


# The same CVE on 139 and 445 is one Samba daemon, not two problems.
def test_one_finding_per_host_not_per_port():
    shared = [_cve("CVE-2007-2446", "CRITICAL", 10.0)]
    result = _result([_host_with(_port(139, vulns=shared), _port(445, vulns=shared))])

    c = techreport.build_content(result)

    assert len(c.findings_rows) == 1
    row = c.findings_rows[0]
    assert row["ports"] == ["139/tcp", "445/tcp"] and row["port"] == "139/tcp, 445/tcp"
    assert c.severity_counts["CRITICAL"] == 1
    # the instance count is still disclosed, never silently dropped
    assert c.meta["Findings"] == "1 (2 across all ports)"


# Section 1 must agree with section 5: an unscored CVE is not "info".
def test_unknown_severity_is_counted_as_unknown_not_info():
    result = _result([_host_with(_port(139, vulns=[_cve("CVE-2007-4044", "UNKNOWN", None)]))])

    c = techreport.build_content(result)

    assert c.severity_counts["UNKNOWN"] == 1
    assert c.severity_counts["INFO"] == 0
    assert sum(c.severity_counts.values()) == len(c.findings_rows)
    # matched against "3.X - 4.X", so it lands in the unconfirmed group
    assert c.severity_unconfirmed["UNKNOWN"] == 1 and c.severity_confirmed["UNKNOWN"] == 0
    assert "unconfirmed" in c.summary_paragraphs[1]


def test_confidence_reflects_how_precise_the_version_was():
    result = _result([_host_with(
        _port(139, version="3.X - 4.X", vulns=[_cve("CVE-1", "HIGH", 8.0)]),          # a range
        _port(21, product="vsftpd", version="2.0.8 or later", vulns=[_cve("CVE-2", "HIGH", 8.0)]),
        _port(8200, product="MiniDLNA", version="1.1.4", vulns=[_cve("CVE-3", "LOW", 2.0)]),
        _port(23, product="BusyBox", version="", vulns=[_cve("CS-RULE-001", "HIGH", None, source="rule")]),
    )])

    by_id = {r["id"]: r["confidence"] for r in techreport.build_content(result).findings_rows}

    assert by_id["CVE-1"] == techreport.UNCONFIRMED
    assert by_id["CVE-2"] == techreport.UNCONFIRMED  # "or later" is not a version
    assert by_id["CVE-3"] == techreport.VERSION_MATCH
    assert by_id["CS-RULE-001"] == techreport.OBSERVED


def test_summary_warns_about_unconfirmed_matches():
    result = _result([_host_with(_port(139, vulns=[_cve("CVE-1", "HIGH", 8.0)]))])
    assert "unconfirmed" in techreport.build_content(result).summary_paragraphs[1]


# "5 / 5" hid the fact that a whole /24 was swept.
def test_addresses_scanned_reports_the_range_not_the_survivors():
    c = techreport.build_content(_result([_host_with(_port(139))]))
    assert c.meta["Addresses scanned"] == "254"
    assert c.meta["Hosts responding"] == "1"


def test_empty_port_table_says_why_it_is_empty():
    from cybersweeper.models import Host

    quiet = techreport.HostSection(host=Host(ip="10.0.0.9"), port_rows=[], findings=[])
    assert techreport._no_ports_note(quiet) == "No open TCP ports were found on this host."

    filtered = techreport.HostSection(host=_host_with(_port(139)), port_rows=[], findings=[])
    assert "report filter" in techreport._no_ports_note(filtered)


# Grouping findings must not shrink the list of places to apply the fix.
def test_remediation_plan_lists_every_affected_port():
    shared = [_cve("CVE-2007-2446", "CRITICAL", 10.0)]
    result = _result([_host_with(_port(139, vulns=shared), _port(445, vulns=shared))])

    plan = techreport.build_content(result).remediation

    assert plan[0]["targets"] == ["10.0.0.1:139", "10.0.0.1:445"]


# An UNKNOWN severity must not crash the renderers.
#
# 2.1.0 gave UNKNOWN its own row in the summary table but never added it to
# SEVERITY_MEANING, so every export of a scan containing an unscored CVE died
# with KeyError: 'UNKNOWN'. Render both formats for real, not just the model.
def test_writers_render_a_finding_with_no_cvss_score():
    import tempfile

    pytest.importorskip("reportlab")
    pytest.importorskip("docx")
    result = _result([_host_with(_port(139, vulns=[_cve("CVE-2007-4044", "UNKNOWN", None)]))])

    with tempfile.TemporaryDirectory() as tmp:
        for fmt in ("pdf", "docx"):
            out = techreport.write(result, fmt, f"{tmp}/r.{fmt}")
            assert out.exists() and out.stat().st_size > 3000


def test_every_severity_has_a_meaning():
    for severity in techreport.SEVERITIES:
        assert techreport.SEVERITY_MEANING.get(severity), severity


# One speculative CVE must not decide how the whole network is described.
def test_overall_rating_ignores_unconfirmed_matches():
    samba = _port(139, product="Samba smbd", version="3.X - 4.X",
                  vulns=[_cve("CVE-2007-2446", "CRITICAL", 10.0)])          # a range
    telnet = _port(23, product="BusyBox telnetd", version="1.14.0 or later",
                   vulns=[_cve("CS-RULE-001", "HIGH", None, source="rule")])  # observed
    c = techreport.build_content(_result([_host_with(samba, telnet)]))

    assert c.overall_risk == "HIGH"          # from the rule the scan actually saw
    assert c.unconfirmed_risk == "CRITICAL"  # reported, but not folded in
    assert c.severity_confirmed["CRITICAL"] == 0
    assert c.severity_unconfirmed["CRITICAL"] == 1
    assert "excluded from the rating above" in c.meta["Unconfirmed CVE matches"]
    assert "CRITICAL" in c.meta["Unconfirmed CVE matches"]


# A CVE matched against an exact build still counts towards the rating.
def test_precise_version_match_does_count_as_confirmed():
    dlna = _port(8200, product="MiniDLNA", version="1.1.4",
                 vulns=[_cve("CVE-2023-1", "CRITICAL", 9.5)])
    c = techreport.build_content(_result([_host_with(dlna)]))

    assert c.overall_risk == "CRITICAL"
    assert c.severity_confirmed["CRITICAL"] == 1
    assert "Unconfirmed CVE matches" not in c.meta


def test_host_inventory_risk_agrees_with_the_overall_rating():
    samba = _port(139, vulns=[_cve("CVE-2007-2446", "CRITICAL", 10.0)])
    c = techreport.build_content(_result([_host_with(samba)]))

    assert c.inventory_rows[0][4] == "none confirmed"
    assert c.overall_risk == "NONE"


def test_summary_explains_both_groups():
    samba = _port(139, vulns=[_cve("CVE-2007-2446", "CRITICAL", 10.0)])
    telnet = _port(23, vulns=[_cve("CS-RULE-001", "HIGH", None, source="rule")])
    para = techreport.build_content(_result([_host_with(samba, telnet)])).summary_paragraphs[1]

    assert "1 is confirmed" in para
    assert "The remaining 1 is unconfirmed" in para
    assert "may well not apply" in para

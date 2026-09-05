import csv
import json

from cybersweep import report, storage
from cybersweep.models import ScanOptions, ScanResult

# --------------------------------------------------------------------------- #
# storage
# --------------------------------------------------------------------------- #


def test_save_and_load_roundtrip(tmp_path, sample_result):
    with storage.Database(tmp_path / "t.db") as db:
        scan_id = db.save_scan(sample_result)
        assert scan_id == 1 and sample_result.scan_id == 1
        loaded = db.load_scan(scan_id)

    assert loaded is not None
    assert loaded.options.target == "192.168.1.0/28"
    assert loaded.engine == "socket"
    assert loaded.notes == ["test note"]
    assert [h.ip for h in loaded.hosts] == ["192.168.1.10", "192.168.1.2", "192.168.1.3"]
    h = loaded.hosts[0]
    assert h.mac == "AA:BB:CC:DD:EE:FF" and h.vendor == "Acme"
    assert [p.number for p in h.ports] == [22, 23, 80]
    v = h.ports[0].vulnerabilities[0]
    assert v.cve_id == "CVE-2023-38408" and v.cvss_score == 9.8 and v.severity == "CRITICAL"
    assert loaded.hosts[2].is_up is False


def test_list_history_and_delete(tmp_path, sample_result):
    with storage.Database(tmp_path / "t.db") as db:
        db.save_scan(sample_result)
        db.save_scan(ScanResult(options=ScanOptions(target="10.0.0.1"), engine="nmap"))
        scans = db.list_scans()
        assert [s["id"] for s in scans] == [2, 1]
        assert scans[1]["hosts_up"] == 2 and scans[1]["open_ports"] == 3 and scans[1]["vulns"] == 2
        assert db.latest_scan_id() == 2
        assert db.delete_scan(2) is True
        assert db.delete_scan(2) is False
        assert db.load_scan(2) is None
        assert db.latest_scan_id() == 1


def test_delete_cascades(tmp_path, sample_result):
    with storage.Database(tmp_path / "t.db") as db:
        db.save_scan(sample_result)
        db.delete_scan(1)
        for table in ("hosts", "ports", "vulnerabilities"):
            assert db.conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_default_db_path_uses_env(tmp_path):
    db = storage.Database()
    assert db.path.startswith(str(tmp_path / "home"))
    db.close()


def test_export_csv(tmp_path, sample_result):
    path = storage.export_csv(sample_result, tmp_path / "out" / "r.csv")
    rows = list(csv.DictReader(path.open(encoding="utf-8")))
    assert set(storage.CSV_COLUMNS) == set(rows[0].keys())
    # host1: 22 (1 finding), 23 (1 finding) ; host2: 443 (no finding) ; host3: down row
    assert len(rows) == 4
    assert rows[0]["finding_id"] == "CVE-2023-38408" and rows[0]["cvss_score"] == "9.8"
    assert rows[3]["state"] == "down"


def test_export_csv_all_states(tmp_path, sample_result):
    rows = list(csv.DictReader(storage.export_csv(sample_result, tmp_path / "a.csv", open_only=False).open()))
    assert any(r["port"] == "80" and r["state"] == "closed" for r in rows)


def test_export_json(tmp_path, sample_result):
    data = json.loads(storage.export_json(sample_result, tmp_path / "r.json").read_text())
    assert data["options"]["target"] == "192.168.1.0/28"
    assert data["hosts"][0]["ports"][0]["vulnerabilities"][0]["cve_id"] == "CVE-2023-38408"
    assert data["hosts"][0]["ports"][0]["service_label"] == "OpenSSH 8.9p1"


# --------------------------------------------------------------------------- #
# filters
# --------------------------------------------------------------------------- #


def test_filter_default_hides_down_hosts_and_closed_ports(sample_result):
    hosts = report.ReportFilter().apply(sample_result)
    assert [h.ip for h in hosts] == ["192.168.1.2", "192.168.1.10"]  # sorted by IP
    assert all(p.is_open for h in hosts for p in h.ports)


def test_filter_by_port_service_and_host(sample_result):
    assert [h.ip for h in report.ReportFilter(ports=[443]).apply(sample_result)] == ["192.168.1.2"]
    hosts = report.ReportFilter(services=["openssh"]).apply(sample_result)
    assert len(hosts) == 1 and [p.number for p in hosts[0].ports] == [22]
    assert [h.ip for h in report.ReportFilter(hosts=["server"]).apply(sample_result)] == ["192.168.1.10"]


def test_filter_severity_and_vulnerable(sample_result):
    hosts = report.ReportFilter(min_severity="CRITICAL").apply(sample_result)
    assert [p.number for p in hosts[0].ports] == [22]
    hosts = report.ReportFilter(only_vulnerable=True).apply(sample_result)
    assert [p.number for p in hosts[0].ports] == [22, 23]
    assert report.ReportFilter(min_severity="CRITICAL", hosts=["192.168.1.2"]).apply(sample_result) == []


def test_filter_sorting(sample_result):
    by_ports = report.ReportFilter(sort_by="open_ports").apply(sample_result)
    assert by_ports[0].ip == "192.168.1.10"
    by_sev = report.ReportFilter(sort_by="severity").apply(sample_result)
    assert by_sev[0].ip == "192.168.1.10"


def test_filter_include_down(sample_result):
    hosts = report.ReportFilter(live_only=False, states=[]).apply(sample_result)
    assert len(hosts) == 3


# --------------------------------------------------------------------------- #
# renderers
# --------------------------------------------------------------------------- #


def test_render_text_contains_key_facts(sample_result):
    sample_result.scan_id = 7
    text = report.render_text(sample_result)
    assert "scan #7" in text
    assert "192.168.1.10 (server)" in text
    assert "OpenSSH 8.9p1" in text
    assert "[CRITICAL (9.8)] 22/tcp CVE-2023-38408" in text
    assert "-> Upgrade OpenSSH" in text
    assert "80/tcp" not in text  # closed port hidden by default
    assert "CRITICAL 1" in text and "HIGH 1" in text


def test_render_text_empty_filter(sample_result):
    text = report.render_text(sample_result, report.ReportFilter(hosts=["nope"]))
    assert "No hosts match" in text


def test_render_markdown(sample_result):
    md = report.render_markdown(sample_result)
    assert md.startswith("# CyberSweep report")
    assert "| 22/tcp | open | ssh | OpenSSH 8.9p1 | CRITICAL |" in md
    assert "**CRITICAL** `CVE-2023-38408`" in md


def test_render_html_is_escaped_and_complete(sample_result):
    sample_result.hosts[0].ports[0].banner = "<script>alert(1)</script>"
    html = report.render_html(sample_result)
    assert html.startswith("<!DOCTYPE html>") and html.endswith("</html>")
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-38408" in html
    assert "class='badge CRITICAL'" in html


def test_render_dispatch(sample_result):
    assert report.render(sample_result, "HTML").startswith("<!DOCTYPE")
    assert report.render(sample_result, "md").startswith("#")
    import pytest

    with pytest.raises(ValueError):
        report.render(sample_result, "pdf")

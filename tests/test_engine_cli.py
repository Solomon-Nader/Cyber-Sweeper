import json
from unittest import mock

import pytest

from cybersweeper import cli, engine, portscan, storage
from cybersweeper.models import Host, ScanOptions

# --------------------------------------------------------------------------- #
# engine
# --------------------------------------------------------------------------- #


def test_engine_single_host_real_socket_scan(ssh_server, monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    opts = ScanOptions(target="127.0.0.1", ports=str(ssh_server.port), method="auto",
                       timeout=1, cve_lookup=False)
    events = []
    result = engine.ScanEngine(opts, progress=lambda *a: events.append(a[0])).run()
    assert result.engine == "socket"
    assert result.finished_at is not None
    assert len(result.hosts) == 1 and result.hosts[0].discovery_method == "assumed"
    port = result.hosts[0].open_ports[0]
    assert port.number == ssh_server.port and port.product == "OpenSSH"
    assert events[0] == "prepare" and events[-1] == "done"
    assert "discovery" not in events  # single host skips discovery


def test_engine_multi_host_runs_discovery(monkeypatch):
    fake_hosts = [Host(ip="10.0.0.2", discovery_method="tcp")]
    monkeypatch.setattr(engine.discovery, "discover_hosts", lambda ips, **kw: (fake_hosts, "tcp"))
    fake_scanner = mock.MagicMock(name="scanner")
    fake_scanner.name = "socket"
    fake_scanner.scan_host.side_effect = lambda host, ports, progress=None: host
    monkeypatch.setattr(engine.portscan, "make_scanner", lambda *a, **k: fake_scanner)

    result = engine.ScanEngine(ScanOptions(target="10.0.0.1-3", ports="22")).run()
    assert [h.ip for h in result.hosts] == ["10.0.0.2"]
    assert result.notes[0].startswith("discovery via tcp: 1/3")
    fake_scanner.scan_host.assert_called_once()


def test_engine_no_discovery_flag(monkeypatch):
    fake_scanner = mock.MagicMock()
    fake_scanner.name = "socket"
    fake_scanner.scan_host.side_effect = lambda host, ports, progress=None: host
    monkeypatch.setattr(engine.portscan, "make_scanner", lambda *a, **k: fake_scanner)
    result = engine.ScanEngine(ScanOptions(target="10.0.0.1-2", ports="22", discover=False)).run()
    assert len(result.hosts) == 2 and all(h.discovery_method == "assumed" for h in result.hosts)


def test_engine_cancel_stops_early(monkeypatch):
    fake_scanner = mock.MagicMock()
    fake_scanner.name = "socket"
    eng = engine.ScanEngine(ScanOptions(target="10.0.0.1-5", ports="22", discover=False))

    def scan_host(host, ports, progress=None):
        eng.cancel()
        return host

    fake_scanner.scan_host.side_effect = scan_host
    monkeypatch.setattr(engine.portscan, "make_scanner", lambda *a, **k: fake_scanner)
    result = eng.run()
    assert fake_scanner.scan_host.call_count == 1
    assert "cancelled by user" in result.notes


def test_engine_nmap_failure_falls_back_to_socket(monkeypatch):
    bad = mock.MagicMock()
    bad.name = "nmap"
    bad.scan_host.side_effect = RuntimeError("nmap exploded")
    monkeypatch.setattr(engine.portscan, "make_scanner", lambda *a, **k: bad)
    fallback = mock.MagicMock()
    fallback.scan_host.side_effect = lambda host, ports, progress=None: host
    monkeypatch.setattr(engine.portscan, "SocketScanner", lambda **kw: fallback)
    result = engine.ScanEngine(ScanOptions(target="10.0.0.1", ports="22")).run()
    assert result.engine == "socket"
    assert any("nmap error" in n for n in result.notes)
    fallback.scan_host.assert_called_once()


def test_engine_cve_lookup_uses_injected_client(monkeypatch):
    fake_scanner = mock.MagicMock()
    fake_scanner.name = "socket"

    def scan_host(host, ports, progress=None):
        host.ports = [portscan.Port(number=22, state="open", service="ssh", product="OpenSSH", version="8.9")]
        return host

    fake_scanner.scan_host.side_effect = scan_host
    monkeypatch.setattr(engine.portscan, "make_scanner", lambda *a, **k: fake_scanner)
    client = mock.MagicMock()
    client.errors = ["NVD lookup failed"]
    client.search.return_value = []
    result = engine.ScanEngine(ScanOptions(target="10.0.0.1", ports="22", cve_lookup=True),
                               nvd_client=client).run()
    client.search.assert_called_once_with("OpenSSH", "8.9")
    assert "NVD lookup failed" in result.notes


def test_environment_report_keys():
    info = engine.environment_report()
    assert {"python", "platform", "nmap binary", "python-nmap", "local ip"} <= set(info)


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #


def test_cli_check(capsys):
    assert cli.main(["check"]) == 0
    assert "nmap binary" in capsys.readouterr().out


def test_cli_scan_saves_and_reports(ssh_server, tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    db = tmp_path / "cli.db"
    csv_out = tmp_path / "out.csv"
    html_out = tmp_path / "out.html"
    json_out = tmp_path / "out.json"
    rc = cli.main(["--db", str(db), "--no-banner", "scan", "127.0.0.1", "-p", str(ssh_server.port),
                   "--csv", str(csv_out), "--html", str(html_out), "--json", str(json_out)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "OpenSSH 8.9p1" in out and "Saved as scan #1" in out
    assert csv_out.exists() and html_out.exists()
    assert json.loads(json_out.read_text())["hosts"][0]["ip"] == "127.0.0.1"

    # history + report from the same database
    assert cli.main(["--db", str(db), "history"]) == 0
    assert "127.0.0.1" in capsys.readouterr().out
    assert cli.main(["--db", str(db), "report", "--format", "markdown"]) == 0
    assert "# Cyber Sweeper report - scan #1" in capsys.readouterr().out
    assert cli.main(["--db", str(db), "report", "1", "--service", "nothing-matches"]) == 0
    assert "No hosts match" in capsys.readouterr().out
    assert cli.main(["--db", str(db), "report", "1", "-f", "csv", "-o", str(tmp_path / "rep.csv")]) == 0
    assert (tmp_path / "rep.csv").exists()
    assert cli.main(["--db", str(db), "delete", "1"]) == 0
    assert cli.main(["--db", str(db), "delete", "1"]) == 1


def test_cli_scan_no_save(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    db = tmp_path / "x.db"
    rc = cli.main(["--db", str(db), "--no-banner", "-q", "scan", "127.0.0.1", "-p", "1", "--no-save",
                   "-t", "0.2"])
    assert rc == 0
    with storage.Database(db) as d:
        assert d.latest_scan_id() is None


def test_cli_bad_target_returns_2(capsys):
    assert cli.main(["--no-banner", "scan", "300.1.1.1"]) == 2
    assert "error" in capsys.readouterr().err


def test_cli_nmap_requested_but_missing(monkeypatch, capsys):
    monkeypatch.setattr(cli.utils, "nmap_available", lambda: False)
    assert cli.main(["--no-banner", "scan", "127.0.0.1", "-m", "nmap"]) == 2
    assert "nmap" in capsys.readouterr().err


def test_cli_report_without_scans(tmp_path, capsys):
    assert cli.main(["--db", str(tmp_path / "empty.db"), "report"]) == 1
    assert cli.main(["--db", str(tmp_path / "empty.db"), "report", "99"]) == 1
    assert cli.main(["--db", str(tmp_path / "empty.db"), "history"]) == 0
    assert "No scans" in capsys.readouterr().out


def test_cli_discover(monkeypatch, capsys):
    monkeypatch.setattr(cli.discovery, "discover_hosts",
                        lambda ips, **kw: ([Host(ip="10.0.0.1", hostname="a")], "tcp"))
    assert cli.main(["--no-banner", "discover", "10.0.0.0/30"]) == 0
    assert "10.0.0.1" in capsys.readouterr().out


def test_cli_requires_command():
    with pytest.raises(SystemExit):
        cli.main([])


def test_console_progress_disabled_when_not_tty():
    p = cli.ConsoleProgress(enabled=True)
    p("ports", 1, 2, "x")  # should not raise even if stderr is not a tty


def test_cli_check_reports_missing_report_library(monkeypatch, capsys):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "reportlab":
            raise ImportError("no reportlab")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    rc = cli.main(["check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "reportlab (PDF reports)" in out and "NOT installed" in out
    assert "pip install" in out and "reportlab" in out.split("Missing Python packages")[1]


def test_cli_check_all_present(capsys):
    rc = cli.main(["check"])
    out = capsys.readouterr().out
    assert rc == 0 and "All required Python packages are present" in out

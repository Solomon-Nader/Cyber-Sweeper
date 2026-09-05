"""GUI smoke tests. Skipped automatically when Tk or a display is unavailable."""

import os
import sys

import pytest

tk = pytest.importorskip("tkinter")

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    pytest.skip("no X display available", allow_module_level=True)


@pytest.fixture
def app(tmp_path):
    from cybersweep import gui

    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"cannot open display: {exc}")
    root.withdraw()
    application = gui.CyberSweepApp(root, db_path=str(tmp_path / "gui.db"))
    yield application
    root.destroy()


def test_tables_populate_from_result(app, sample_result):
    app.result = sample_result
    app.refresh_tables()
    port_rows = app.ports_tree.get_children()
    vuln_rows = app.vuln_tree.get_children()
    assert len(port_rows) == 3  # 22, 23 on host1 + 443 on host2 (closed 80 hidden)
    assert len(vuln_rows) == 2
    values = app.ports_tree.item(port_rows[-1], "values")
    assert values[0] == "192.168.1.10" and values[7] in ("CRITICAL", "HIGH")


def test_filters_apply(app, sample_result):
    app.result = sample_result
    app.filter_var.set("openssh")
    assert len(app.ports_tree.get_children()) == 1
    app.filter_var.set("")
    app.min_sev_var.set("CRITICAL")
    app.refresh_tables()
    assert len(app.ports_tree.get_children()) == 1
    app.min_sev_var.set("any")
    app.open_only_var.set(False)
    app.refresh_tables()
    assert len(app.ports_tree.get_children()) == 4  # closed port 80 now visible


def test_scan_roundtrip_through_queue(app, ssh_server, monkeypatch):
    from cybersweep import portscan

    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    app.target_var.set("127.0.0.1")
    app.ports_var.set(str(ssh_server.port))
    app.method_var.set("socket")
    app.start_scan()
    app.worker.join(timeout=15)
    assert not app.worker.is_alive()
    # drain the queue the way the mainloop would
    app._poll_queue()
    assert app.result is not None
    assert app.result.scan_id == 1
    assert len(app.ports_tree.get_children()) == 1
    assert str(app.start_btn["state"]) == "normal"


def test_invalid_target_shows_error(app, monkeypatch):
    from cybersweep import gui

    shown = []
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: shown.append(a))
    app.target_var.set("999.1.1.1")
    app.start_scan()
    assert shown and app.worker is None

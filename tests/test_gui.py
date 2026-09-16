# GUI smoke tests. Skipped automatically when Tk or a display is unavailable.

import os
import sys

import pytest

tk = pytest.importorskip("tkinter")

if sys.platform.startswith("linux") and not os.environ.get("DISPLAY"):
    pytest.skip("no X display available", allow_module_level=True)


@pytest.fixture
def app(tmp_path):
    from cybersweeper import gui

    try:
        root = tk.Tk()
    except tk.TclError as exc:  # pragma: no cover
        pytest.skip(f"cannot open display: {exc}")
    root.withdraw()
    application = gui.CyberSweeperApp(root, db_path=str(tmp_path / "gui.db"))
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
    from cybersweeper import portscan

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
    from cybersweeper import gui

    shown = []
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: shown.append(a))
    app.target_var.set("999.1.1.1")
    app.start_scan()
    assert shown and app.worker is None


def test_apply_icon_uses_every_prescaled_size(app):
    from cybersweeper import gui

    assert (gui.ASSETS_DIR / "cybersweeper.ico").exists()
    for name in gui.ICON_PNGS:
        assert (gui.ASSETS_DIR / name).exists(), name
    gui.apply_icon(app.master)  # must not raise, even headless
    icons = getattr(app.master, "_cybersweeper_icons", [])
    assert len(icons) == len(gui.ICON_PNGS)
    # Tk must be given real title-bar sizes, not left to shrink the 256 px art.
    assert sorted(i.width() for i in icons) == [16, 24, 32, 48, 64, 256]


def test_icon_file_sizes_cover_windows_title_bar_and_taskbar():
    Image = pytest.importorskip("PIL.Image")  # only needed to inspect the .ico

    from cybersweeper import gui

    with Image.open(gui.ASSETS_DIR / "cybersweeper.ico") as ico:
        sizes = {w for w, _ in ico.info["sizes"]}
    assert {16, 20, 24, 32, 48, 256} <= sizes


# A crash inside the writer used to reach Tkinter and leave no file and no message.
def test_failed_export_reports_the_error_instead_of_doing_nothing(app, sample_result, monkeypatch, tmp_path):
    from cybersweeper import gui

    app.result = sample_result  # export() asks for a scan first, via a blocking dialog
    monkeypatch.setattr(gui.messagebox, "showinfo", lambda *a, **k: None)
    monkeypatch.setattr(gui.filedialog, "asksaveasfilename", lambda **k: str(tmp_path / "r.pdf"))
    monkeypatch.setattr(gui.techreport, "write",
                        lambda *a, **k: (_ for _ in ()).throw(KeyError("UNKNOWN")))
    shown = []
    monkeypatch.setattr(gui.messagebox, "showerror", lambda *a, **k: shown.append(a))

    app.export("pdf")  # must not raise

    assert shown and "KeyError" in shown[0][1]
    assert "failed" in app.status_var.get().lower()

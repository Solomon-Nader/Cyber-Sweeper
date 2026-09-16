# Tkinter graphical interface for Cyber Sweeper.
#
# The GUI is a thin layer over ScanEngine: the scan
# runs in a background thread and posts progress/result messages to a queue that
# the Tk main loop drains every 100 ms, so the window stays responsive.

from __future__ import annotations

import logging
import queue
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Optional

from cybersweeper import __version__, config, netinfo, report, storage, techreport, utils
from cybersweeper.engine import ScanEngine
from cybersweeper.models import SEVERITY_ORDER, ScanOptions, ScanResult

log = logging.getLogger("cybersweeper.gui")

SEVERITY_COLOURS = {"CRITICAL": "#7f1d1d", "HIGH": "#c2410c", "MEDIUM": "#b45309",
                    "LOW": "#2563eb", "INFO": "#4b5563"}


# Main application window.
class CyberSweeperApp(ttk.Frame):
    def __init__(self, master: tk.Tk, db_path: Optional[str] = None) -> None:
        super().__init__(master, padding=8)
        self.master = master
        self.db_path = db_path
        self.queue: queue.Queue = queue.Queue()
        self.engine: Optional[ScanEngine] = None
        self.worker: Optional[threading.Thread] = None
        self.result: Optional[ScanResult] = None

        master.title(f"Cyber Sweeper {__version__} - Network Inspector")
        master.geometry("1100x720")
        master.minsize(900, 600)
        self.pack(fill="both", expand=True)
        self._build_widgets()
        self.after(100, self._poll_queue)
        self.after(200, self.detect_network)

    # ------------------------------------------------------------------ #
    # Layout
    # ------------------------------------------------------------------ #

    def _build_widgets(self) -> None:
        # --- current network ---------------------------------------------
        netbar = ttk.LabelFrame(self, text="Current network", padding=(8, 4))
        netbar.pack(fill="x", pady=(0, 6))
        self.network: Optional[netinfo.NetworkInfo] = None
        self.network_var = tk.StringVar(value="Detecting the network this machine is connected to...")
        ttk.Label(netbar, textvariable=self.network_var, anchor="w").pack(side="left", fill="x", expand=True)
        self.use_net_btn = ttk.Button(netbar, text="Use as target", command=self.use_network_target,
                                      state="disabled")
        self.use_net_btn.pack(side="right")
        ttk.Button(netbar, text="Detect again", command=self.detect_network).pack(side="right", padx=4)

        # --- scan options -------------------------------------------------
        opts = ttk.LabelFrame(self, text="Scan options", padding=8)
        opts.pack(fill="x")

        ttk.Label(opts, text="Target").grid(row=0, column=0, sticky="w")
        self.target_var = tk.StringVar(value="")
        ttk.Entry(opts, textvariable=self.target_var, width=32).grid(row=0, column=1, sticky="we", padx=4)

        ttk.Label(opts, text="Ports").grid(row=0, column=2, sticky="w")
        self.ports_var = tk.StringVar(value="common")
        ttk.Combobox(opts, textvariable=self.ports_var, width=16,
                     values=["common", "top100", "top1000", "all", "22,80,443", "1-1024"]).grid(
            row=0, column=3, padx=4)

        ttk.Label(opts, text="Engine").grid(row=0, column=4, sticky="w")
        self.method_var = tk.StringVar(value="auto")
        ttk.Combobox(opts, textvariable=self.method_var, width=8, state="readonly",
                     values=["auto", "socket", "nmap"]).grid(row=0, column=5, padx=4)

        ttk.Label(opts, text="Timeout (s)").grid(row=0, column=6, sticky="w")
        self.timeout_var = tk.DoubleVar(value=config.DEFAULT_CONNECT_TIMEOUT)
        ttk.Spinbox(opts, textvariable=self.timeout_var, from_=0.2, to=10, increment=0.2,
                    width=6).grid(row=0, column=7, padx=4)

        self.discover_var = tk.BooleanVar(value=True)
        self.service_var = tk.BooleanVar(value=True)
        self.cve_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(opts, text="Host discovery", variable=self.discover_var).grid(row=1, column=1, sticky="w", pady=(6, 0))
        ttk.Checkbutton(opts, text="Service detection", variable=self.service_var).grid(row=1, column=3, sticky="w", pady=(6, 0))
        ttk.Checkbutton(opts, text="CVE lookup (online)", variable=self.cve_var).grid(row=1, column=5, columnspan=2, sticky="w", pady=(6, 0))

        btns = ttk.Frame(opts)
        btns.grid(row=0, column=8, rowspan=2, padx=(16, 0))
        self.start_btn = ttk.Button(btns, text="Start scan", command=self.start_scan)
        self.start_btn.pack(fill="x")
        self.stop_btn = ttk.Button(btns, text="Stop", command=self.stop_scan, state="disabled")
        self.stop_btn.pack(fill="x", pady=(4, 0))
        opts.columnconfigure(1, weight=1)

        # --- progress -----------------------------------------------------
        prog = ttk.Frame(self)
        prog.pack(fill="x", pady=6)
        self.progress = ttk.Progressbar(prog, mode="determinate", length=320)
        self.progress.pack(side="left")
        self.status_var = tk.StringVar(value=config.LEGAL_NOTICE)
        ttk.Label(prog, textvariable=self.status_var, anchor="w").pack(side="left", fill="x",
                                                                       expand=True, padx=8)

        # --- filter bar ---------------------------------------------------
        flt = ttk.Frame(self)
        flt.pack(fill="x")
        ttk.Label(flt, text="Filter").pack(side="left")
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.refresh_tables())
        ttk.Entry(flt, textvariable=self.filter_var, width=30).pack(side="left", padx=4)
        ttk.Label(flt, text="Min severity").pack(side="left", padx=(8, 0))
        self.min_sev_var = tk.StringVar(value="any")
        cb = ttk.Combobox(flt, textvariable=self.min_sev_var, width=9, state="readonly",
                          values=["any", "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        cb.pack(side="left", padx=4)
        cb.bind("<<ComboboxSelected>>", lambda *_: self.refresh_tables())
        self.open_only_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(flt, text="Open ports only", variable=self.open_only_var,
                        command=self.refresh_tables).pack(side="left", padx=8)
        ttk.Button(flt, text="History...", command=self.show_history).pack(side="right", padx=(8, 0))
        for fmt, label in (("json", "JSON"), ("csv", "CSV"), ("html", "HTML"), ("docx", "Word"), ("pdf", "PDF")):
            ttk.Button(flt, text=label, width=6,
                       command=lambda f=fmt: self.export(f)).pack(side="right", padx=2)
        ttk.Label(flt, text="Export:").pack(side="right", padx=(8, 2))

        # --- notebook -----------------------------------------------------
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, pady=(6, 0))

        self.ports_tree = self._make_tree(nb, (
            ("ip", "IP", 120), ("hostname", "Hostname", 150), ("port", "Port", 70),
            ("state", "State", 70), ("service", "Service", 110), ("product", "Product / version", 200),
            ("banner", "Banner", 260), ("risk", "Risk", 80)))
        nb.add(self.ports_tree.master, text="Hosts & ports")

        self.vuln_tree = self._make_tree(nb, (
            ("ip", "IP", 120), ("port", "Port", 70), ("id", "Finding", 150), ("severity", "Severity", 80),
            ("cvss", "CVSS", 60), ("summary", "Summary", 420), ("recommendation", "Recommendation", 300)))
        nb.add(self.vuln_tree.master, text="Findings")
        self.vuln_tree.bind("<Double-1>", self._show_finding_details)

        log_frame = ttk.Frame(nb)
        self.log = tk.Text(log_frame, height=10, wrap="word", state="disabled")
        self.log.pack(fill="both", expand=True)
        nb.add(log_frame, text="Log")

        for sev, colour in SEVERITY_COLOURS.items():
            self.ports_tree.tag_configure(sev, foreground=colour)
            self.vuln_tree.tag_configure(sev, foreground=colour)

    @staticmethod
    def _make_tree(parent, columns) -> ttk.Treeview:
        frame = ttk.Frame(parent)
        ids = [c[0] for c in columns]
        tree = ttk.Treeview(frame, columns=ids, show="headings", selectmode="browse")
        for cid, title, width in columns:
            tree.heading(cid, text=title, command=lambda c=cid, t=tree: CyberSweeperApp._sort_tree(t, c, False))
            tree.column(cid, width=width, anchor="w", stretch=(cid in ("banner", "summary", "recommendation")))
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=vsb.set, xscrollcommand=hsb.set)
        tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="we")
        frame.rowconfigure(0, weight=1)
        frame.columnconfigure(0, weight=1)
        return tree

    @staticmethod
    def _sort_tree(tree: ttk.Treeview, col: str, reverse: bool) -> None:
        items = [(tree.set(k, col), k) for k in tree.get_children("")]

        def key(item):
            v = item[0]
            try:
                return (0, float(v))
            except ValueError:
                return (1, v.lower())

        items.sort(key=key, reverse=reverse)
        for idx, (_, k) in enumerate(items):
            tree.move(k, "", idx)
        tree.heading(col, command=lambda: CyberSweeperApp._sort_tree(tree, col, not reverse))

    # ------------------------------------------------------------------ #
    # Network detection
    # ------------------------------------------------------------------ #

    # Detect the connected network in a worker thread (it runs external commands).
    def detect_network(self) -> None:
        self.network_var.set("Detecting the network this machine is connected to...")
        self.use_net_btn.configure(state="disabled")
        threading.Thread(target=lambda: self.queue.put(("network", netinfo.detect_network())),
                         daemon=True).start()

    def _network_detected(self, net: netinfo.NetworkInfo) -> None:
        self.network = net
        self.network_var.set(net.describe())
        if net.connected and net.cidr:
            self.use_net_btn.configure(state="normal")
            if not self.target_var.get().strip():
                self.target_var.set(net.cidr)  # auto-target on first detection
            self._log(f"network: {net.describe()} [{net.method}]")
            for n in net.notes:
                self._log(f"network note: {n}")
        else:
            self._log("network: not connected - enter a target manually or connect to a network")

    def use_network_target(self) -> None:
        if self.network and self.network.cidr:
            self.target_var.set(self.network.cidr)

    # ------------------------------------------------------------------ #
    # Scanning
    # ------------------------------------------------------------------ #

    def _log(self, text: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", text + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def start_scan(self) -> None:
        if self.worker and self.worker.is_alive():
            return
        target = self.target_var.get().strip()
        if not target:
            if self.network and self.network.connected and self.network.cidr:
                target = self.network.cidr
                self.target_var.set(target)
            else:
                messagebox.showwarning("Cyber Sweeper", "No network detected. Connect to Wi-Fi/Ethernet "
                                       "and click 'Detect again', or enter a target manually.")
                return
        try:
            ips = utils.parse_targets(target)
            utils.parse_ports(self.ports_var.get())
        except (utils.TargetError, utils.PortError) as exc:
            messagebox.showerror("Invalid input", str(exc))
            return
        if len(ips) > 1 and not messagebox.askyesno(
                "Authorisation", f"You are about to scan {len(ips)} addresses.\n\n"
                "Confirm that you are authorised to scan this network."):
            return
        method = self.method_var.get()
        if method == "nmap" and not (utils.nmap_available() and utils.python_nmap_available()):
            messagebox.showerror("nmap missing", "nmap / python-nmap is not available. "
                                 "Install nmap or choose the socket engine.")
            return

        opts = ScanOptions(
            target=target, ports=self.ports_var.get(), method=method,
            discover=self.discover_var.get(), service_detection=self.service_var.get(),
            cve_lookup=self.cve_var.get(), timeout=float(self.timeout_var.get()),
        )
        self._auto_note = (f"target auto-detected: {self.network.describe()}"
                           if self.network and self.network.connected and target == self.network.cidr else "")
        self.engine = ScanEngine(opts, progress=self._progress_from_thread)
        self.worker = threading.Thread(target=self._run_engine, daemon=True)
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.progress.configure(value=0)
        self._log(f"--- scan started: {target} ports={opts.ports} engine={method}")
        self.worker.start()

    def _run_engine(self) -> None:
        try:
            result = self.engine.run()
            self.queue.put(("result", result))
        except Exception as exc:  # show any failure in the UI instead of dying silently
            self.queue.put(("error", str(exc)))

    def _progress_from_thread(self, phase: str, done: int, total: int, message: str) -> None:
        self.queue.put(("progress", (phase, done, total, message)))

    def stop_scan(self) -> None:
        if self.engine:
            self.engine.cancel()
            self.status_var.set("Stopping...")

    def _poll_queue(self) -> None:
        try:
            while True:
                kind, payload = self.queue.get_nowait()
                if kind == "progress":
                    phase, done, total, message = payload
                    if total:
                        self.progress.configure(maximum=total, value=done)
                    self.status_var.set(f"[{phase}] {message}")
                    if phase in ("discovery", "portscan", "vulns", "done") and (
                            phase != "ports"):
                        if phase != "discovery" or done == total:
                            self._log(f"[{phase}] {message}")
                elif kind == "network":
                    self._network_detected(payload)
                elif kind == "result":
                    self._scan_finished(payload)
                elif kind == "error":
                    self._scan_failed(payload)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _scan_finished(self, result: ScanResult) -> None:
        if getattr(self, "_auto_note", ""):
            result.notes.insert(0, self._auto_note)
        self.result = result
        try:
            with storage.Database(self.db_path) as db:
                db.save_scan(result)
            saved = f"saved as scan #{result.scan_id}"
        except Exception as exc:  # pragma: no cover - disk problems
            saved = f"not saved ({exc})"
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.progress.configure(value=self.progress["maximum"])
        summary = (f"{len(result.live_hosts)} host(s) up, {result.total_open_ports} open port(s), "
                   f"{result.total_vulnerabilities} finding(s) in {utils.human_duration(result.duration)} - {saved}")
        self.status_var.set(summary)
        self._log(summary)
        for note in result.notes:
            self._log(f"note: {note}")
        self.refresh_tables()

    def _scan_failed(self, message: str) -> None:
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Scan failed")
        self._log(f"ERROR: {message}")
        messagebox.showerror("Scan failed", message)

    # ------------------------------------------------------------------ #
    # Results display
    # ------------------------------------------------------------------ #

    def _current_filter(self) -> report.ReportFilter:
        text = self.filter_var.get().strip()
        min_sev = self.min_sev_var.get()
        flt = report.ReportFilter(states=["open"] if self.open_only_var.get() else [],
                                  min_severity=None if min_sev == "any" else min_sev)
        if text:
            # match against IP/hostname OR service/product
            flt.hosts = []
            flt.services = []
            self._free_text = text.lower()
        else:
            self._free_text = ""
        return flt

    def refresh_tables(self) -> None:
        for tree in (self.ports_tree, self.vuln_tree):
            tree.delete(*tree.get_children())
        if not self.result:
            return
        flt = self._current_filter()
        text = self._free_text
        for host in flt.apply(self.result):
            for p in host.ports:
                hay = f"{host.ip} {host.hostname} {p.number} {p.service} {p.product} {p.version} {p.banner}".lower()
                if text and text not in hay:
                    continue
                risk = max((v.severity for v in p.vulnerabilities),
                           key=lambda s: SEVERITY_ORDER.get(s, 0), default="")
                self.ports_tree.insert("", "end", values=(
                    host.ip, host.hostname, f"{p.number}/{p.protocol}", p.state, p.service,
                    p.service_label if p.product else "", p.banner, risk), tags=(risk,))
                for v in sorted(p.vulnerabilities, key=lambda v: SEVERITY_ORDER.get(v.severity, 0), reverse=True):
                    self.vuln_tree.insert("", "end", values=(
                        host.ip, p.number, v.cve_id, v.severity,
                        v.cvss_score if v.cvss_score is not None else "", v.summary, v.recommendation),
                        tags=(v.severity,))
            if not host.ports and not text and not self.open_only_var.get():
                self.ports_tree.insert("", "end", values=(host.ip, host.hostname, "", "up", "", "", "", ""))

    def _show_finding_details(self, _event=None) -> None:
        sel = self.vuln_tree.selection()
        if not sel:
            return
        ip, port, fid, sev, cvss, summary, rec = self.vuln_tree.item(sel[0], "values")
        url = f"https://nvd.nist.gov/vuln/detail/{fid}" if fid.startswith("CVE-") else ""
        messagebox.showinfo(f"{fid} - {sev}",
                            f"Host: {ip}  port {port}\nCVSS: {cvss or 'n/a'}\n\n{summary}\n\n"
                            f"Recommendation: {rec}\n{url}")

    # ------------------------------------------------------------------ #
    # Export / history
    # ------------------------------------------------------------------ #

    def export(self, fmt: str) -> None:
        if not self.result:
            messagebox.showinfo("Cyber Sweeper", "Run or load a scan first.")
            return
        ext = {"csv": ".csv", "html": ".html", "json": ".json", "pdf": ".pdf", "docx": ".docx"}[fmt]
        names = {"pdf": "PDF technical report", "docx": "Word technical report"}
        stem = "cybersweeper_report" if fmt in names else "cybersweeper_scan"
        path = filedialog.asksaveasfilename(defaultextension=ext, filetypes=[(names.get(fmt, fmt.upper()), "*" + ext)],
                                            initialfile=f"{stem}_{self.result.scan_id or 'latest'}{ext}")
        if not path:
            return
        flt = self._current_filter()
        if fmt == "csv":
            storage.export_csv(self.result, path, open_only=self.open_only_var.get())
        elif fmt == "json":
            storage.export_json(self.result, path)
        elif fmt in ("pdf", "docx"):
            try:
                techreport.write(self.result, fmt, path, flt)
            except Exception as exc:  # a failed export must never look like success
                log.exception("%s export failed", fmt)
                messagebox.showerror("Export failed", f"{type(exc).__name__}: {exc}")
                self.status_var.set(f"Export failed: {exc}")
                self._log(f"{fmt.upper()} export FAILED: {type(exc).__name__}: {exc}")
                return
        else:
            Path(path).write_text(report.render_html(self.result, flt), encoding="utf-8")
        self._log(f"exported {fmt.upper()} to {path}")
        self.status_var.set(f"Exported {path}")

    def show_history(self) -> None:
        with storage.Database(self.db_path) as db:
            scans = db.list_scans(limit=100)
        win = tk.Toplevel(self.master)
        win.title("Scan history")
        win.geometry("760x360")
        cols = ("id", "started", "target", "ports", "engine", "hosts", "open", "findings")
        tree = ttk.Treeview(win, columns=cols, show="headings")
        for c, w in zip(cols, (50, 150, 200, 90, 70, 60, 60, 70)):
            tree.heading(c, text=c.title())
            tree.column(c, width=w, anchor="w")
        for s in scans:
            tree.insert("", "end", values=(s["id"], s["started_at"].replace("T", " "), s["target"],
                                           s["ports_spec"], s["engine"], s["hosts_up"],
                                           s["open_ports"], s["vulns"]))
        tree.pack(fill="both", expand=True, padx=8, pady=8)

        def load(_event=None):
            sel = tree.selection()
            if not sel:
                return
            scan_id = int(tree.item(sel[0], "values")[0])
            with storage.Database(self.db_path) as db:
                self.result = db.load_scan(scan_id)
            self.status_var.set(f"Loaded scan #{scan_id}")
            self._log(f"loaded scan #{scan_id} from database")
            self.refresh_tables()
            win.destroy()

        def delete():
            sel = tree.selection()
            if not sel:
                return
            scan_id = int(tree.item(sel[0], "values")[0])
            if messagebox.askyesno("Delete", f"Delete scan #{scan_id}?", parent=win):
                with storage.Database(self.db_path) as db:
                    db.delete_scan(scan_id)
                tree.delete(sel[0])

        bar = ttk.Frame(win)
        bar.pack(fill="x", padx=8, pady=(0, 8))
        ttk.Button(bar, text="Load", command=load).pack(side="left")
        ttk.Button(bar, text="Delete", command=delete).pack(side="left", padx=4)
        ttk.Button(bar, text="Close", command=win.destroy).pack(side="right")
        tree.bind("<Double-1>", load)


ASSETS_DIR = Path(__file__).parent / "assets"


ICON_PNGS = ("cybersweeper_16.png", "cybersweeper_24.png", "cybersweeper_32.png",
             "cybersweeper_48.png", "cybersweeper_64.png", "cybersweeper.png")


# Replace Tk's default feather with the Cyber Sweeper orca icon.
#
# Two things matter here. First, iconphoto must be handed *several*
# pre-scaled images: given a single 256x256 PNG, Tk shrinks it to title-bar
# size with a nearest-neighbour "subsample", which is what made earlier
# versions show a blocky smudge. Second, on Windows the title bar and the
# taskbar are driven by the window's WM_SETICON, which iconbitmap
# sets from a multi-resolution .ico - and it has to be called on this window,
# not only as default= (which applies to windows created afterwards).
#
# Failures are ignored; an icon is cosmetic.
def apply_icon(root: tk.Tk) -> None:
    icons = []
    for name in ICON_PNGS:
        path = ASSETS_DIR / name
        if path.exists():
            try:
                icons.append(tk.PhotoImage(file=str(path), master=root))
            except tk.TclError:  # pragma: no cover - unreadable or exotic Tk build
                pass
    root._cybersweeper_icons = icons  # keep references alive for the window's lifetime
    try:
        if icons:
            root.iconphoto(True, *icons)
        ico = ASSETS_DIR / "cybersweeper.ico"
        if ico.exists() and utils.is_windows():
            root.iconbitmap(str(ico))          # this window: title bar + taskbar
            root.iconbitmap(default=str(ico))  # and every dialog opened later
    except tk.TclError:  # pragma: no cover - headless or exotic Tk builds
        pass


# Create the Tk root window and run the application.
def launch(db_path: Optional[str] = None) -> None:
    root = tk.Tk()
    apply_icon(root)
    try:
        ttk.Style().theme_use("clam")
    except tk.TclError:  # pragma: no cover
        pass
    CyberSweeperApp(root, db_path=db_path)
    root.mainloop()


if __name__ == "__main__":  # pragma: no cover
    launch()

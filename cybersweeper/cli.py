# Command line interface for Cyber Sweeper.
#
# Examples::
#
#     cybersweeper check
#     cybersweeper discover 192.168.1.0/24
#     cybersweeper scan 192.168.1.10 -p common
#     cybersweeper scan 192.168.1.0/24 -p 22,80,443,3389 --cve --html report.html --csv out.csv
#     cybersweeper report 3 --format html --min-severity HIGH -o report.html
#     cybersweeper history
#     cybersweeper gui

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional

from cybersweeper import __version__, config, discovery, netinfo, report, storage, techreport, utils
from cybersweeper.engine import ScanEngine, environment_report
from cybersweeper.models import ScanOptions, ScanResult

# --------------------------------------------------------------------------- #
# Argument parsing
# --------------------------------------------------------------------------- #


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cybersweeper",
        description="Cyber Sweeper - network inspector: host discovery, port scanning, "
                    "service identification and vulnerability lookup.",
        epilog=config.LEGAL_NOTICE,
    )
    parser.add_argument("--version", action="version", version=f"cybersweeper {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    parser.add_argument("-q", "--quiet", action="store_true", help="only warnings and errors")
    parser.add_argument("--db", metavar="PATH", help="SQLite database path "
                        "(default: ~/.cybersweeper/cybersweeper.db or $CYBERSWEEPER_HOME)")
    parser.add_argument("--no-banner", action="store_true", help="do not print the ASCII banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")
    sub.required = True

    # check ---------------------------------------------------------------
    sub.add_parser("check", help="show environment information (nmap, python-nmap, current network)")

    # network -------------------------------------------------------------
    p_net = sub.add_parser("network", help="detect the network this machine is connected to")
    p_net.add_argument("--json", action="store_true", help="machine-readable output")

    # discover ------------------------------------------------------------
    p_disc = sub.add_parser("discover", help="find live hosts in a range")
    p_disc.add_argument("target", nargs="?", help="IP, range, CIDR or hostname "
                        "(default: the network this machine is connected to)")
    p_disc.add_argument("-m", "--method", choices=["auto", "tcp", "ping", "arp"], default="auto")
    p_disc.add_argument("-t", "--timeout", type=float, default=config.DEFAULT_CONNECT_TIMEOUT)
    p_disc.add_argument("--threads", type=int, default=config.DEFAULT_THREADS)
    p_disc.add_argument("--max-hosts", type=int, default=config.MAX_HOSTS_WITHOUT_CONFIRMATION)
    p_disc.add_argument("--no-dns", action="store_true", help="skip reverse DNS lookups")

    # scan ----------------------------------------------------------------
    p_scan = sub.add_parser("scan", help="discover hosts, scan ports, identify services")
    p_scan.add_argument("target", nargs="?", help="IP, range (10.0.0.1-50), CIDR (10.0.0.0/24) or "
                        "hostname; comma separated list allowed. Omit it to scan the network this "
                        "machine is connected to (auto-detected)")
    p_scan.add_argument("-p", "--ports", default="top100",
                        help="ports: common | top100 | top1000 | all | 22,80,443 | 1-1024 (default top100)")
    p_scan.add_argument("-m", "--method", choices=["auto", "socket", "nmap"], default="auto",
                        help="scan engine (default auto: nmap when installed, else socket)")
    p_scan.add_argument("--discovery", choices=["auto", "tcp", "ping", "arp"], default="auto",
                        help="host discovery technique for multi-host targets")
    p_scan.add_argument("--no-discovery", action="store_true",
                        help="treat every address as up (like nmap -Pn)")
    p_scan.add_argument("--no-service", action="store_true", help="skip banner grabbing / -sV")
    p_scan.add_argument("--cve", action="store_true",
                        help="look up CVEs in the NVD for identified services (needs internet)")
    p_scan.add_argument("-t", "--timeout", type=float, default=config.DEFAULT_CONNECT_TIMEOUT,
                        help="connect timeout in seconds (default 1.0)")
    p_scan.add_argument("--threads", type=int, default=config.DEFAULT_THREADS,
                        help="concurrent probes for the socket engine (default 100)")
    p_scan.add_argument("--max-hosts", type=int, default=config.MAX_HOSTS_WITHOUT_CONFIRMATION)
    p_scan.add_argument("--no-save", action="store_true", help="do not store the result in the database")
    p_scan.add_argument("--csv", metavar="FILE", help="export flat CSV")
    p_scan.add_argument("--json", metavar="FILE", help="export JSON")
    p_scan.add_argument("--html", metavar="FILE", help="export HTML report")
    p_scan.add_argument("--pdf", metavar="FILE", help="export a PDF technical report")
    p_scan.add_argument("--docx", metavar="FILE", help="export a Word (.docx) technical report")
    p_scan.add_argument("--title", default="Network Security Assessment Report",
                        help="title used in PDF/Word technical reports")
    p_scan.add_argument("--org", default="", help="organisation name printed on technical reports")
    p_scan.add_argument("--all-states", action="store_true",
                        help="show closed/filtered ports too (small scans only)")

    # report --------------------------------------------------------------
    p_rep = sub.add_parser("report", help="render a stored scan with filters")
    p_rep.add_argument("scan_id", nargs="?", type=int, help="scan id (default: latest)")
    p_rep.add_argument("-f", "--format", choices=["text", "markdown", "html", "csv", "json", "pdf", "docx"],
                       default="text", help="pdf/docx produce a full technical report document")
    p_rep.add_argument("-o", "--output", metavar="FILE", help="write to file instead of stdout")
    p_rep.add_argument("--title", default="Network Security Assessment Report",
                       help="title used in PDF/Word technical reports")
    p_rep.add_argument("--org", default="", help="organisation name printed on technical reports")
    p_rep.add_argument("--host", action="append", default=[], help="filter by IP/hostname substring")
    p_rep.add_argument("--port", action="append", default=[], help="filter by port (repeatable)")
    p_rep.add_argument("--service", action="append", default=[], help="filter by service/product substring")
    p_rep.add_argument("--state", action="append", default=[], help="port states to show (default open)")
    p_rep.add_argument("--min-severity", choices=["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"],
                       help="only ports with a finding of at least this severity")
    p_rep.add_argument("--vulnerable", action="store_true", help="only ports with findings")
    p_rep.add_argument("--sort", choices=["ip", "open_ports", "severity"], default="ip")
    p_rep.add_argument("--include-down", action="store_true", help="include hosts that were down")

    # history -------------------------------------------------------------
    p_hist = sub.add_parser("history", help="list stored scans")
    p_hist.add_argument("-n", "--limit", type=int, default=50,
                        help="how many of the most recent scans to list (default 50; 0 lists all)")

    # delete --------------------------------------------------------------
    p_del = sub.add_parser("delete", help="delete a stored scan")
    p_del.add_argument("scan_id", type=int)

    # gui -----------------------------------------------------------------
    sub.add_parser("gui", help="launch the graphical interface")
    return parser


# --------------------------------------------------------------------------- #
# Progress display
# --------------------------------------------------------------------------- #


# Single-line progress indicator for the terminal.
class ConsoleProgress:
    def __init__(self, enabled: bool = True) -> None:
        self.enabled = enabled and sys.stderr.isatty()
        self._last_len = 0

    def __call__(self, phase: str, done: int, total: int, message: str) -> None:
        if not self.enabled:
            return
        if phase == "done":
            self._write(f"[done] {message}")
            sys.stderr.write("\n")
            return
        pct = f" {done * 100 // total:3d}%" if total else ""
        self._write(f"[{phase}]{pct} {message}")

    def _write(self, text: str) -> None:
        text = text[:120]
        pad = " " * max(0, self._last_len - len(text))
        sys.stderr.write("\r" + text + pad)
        sys.stderr.flush()
        self._last_len = len(text)


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #


def _open_db(args) -> storage.Database:
    return storage.Database(args.db) if args.db else storage.Database()


# Detect the current network and return its CIDR, or None when offline.
def _auto_target(what: str) -> Optional[str]:
    net = netinfo.detect_network()
    if not net.connected or not net.cidr:
        print("error: this machine does not appear to be connected to a network, so there is "
              "nothing to " + what + ". Connect to Wi-Fi/Ethernet or give a target explicitly.",
              file=sys.stderr)
        return None
    print(f"{net.describe()}")
    for n in net.notes:
        print(f"  note: {n}")
    print(f"-> auto target: {net.cidr}\n")
    _auto_target.last = net  # type: ignore[attr-defined]
    return net.cidr


_auto_target.last = None  # type: ignore[attr-defined]


def cmd_network(args) -> int:
    net = netinfo.detect_network()
    if args.json:
        print(__import__("json").dumps(net.to_dict(), indent=2))
        return 0 if net.connected else 1
    print(net.describe())
    if net.connected:
        rows = [["Connection", {"wifi": "Wi-Fi", "ethernet": "Ethernet (wired)"}.get(net.kind, "unknown")],
                ["SSID", net.ssid or "-"], ["Interface", net.interface or "-"],
                ["IPv4 address", f"{net.ip}/{net.prefix}"], ["Network", net.cidr],
                ["Scannable hosts", str(net.host_count)], ["Gateway", net.gateway or "-"],
                ["MAC address", net.mac or "-"], ["Detected via", net.method]]
        print(report._table(["PROPERTY", "VALUE"], rows))
        print(f"Scan it with:  cybersweeper scan            (or: cybersweeper scan {net.cidr})")
    for n in net.notes:
        print(f"note: {n}")
    return 0 if net.connected else 1


def cmd_check(args) -> int:
    info = environment_report()
    net = netinfo.detect_network()
    info["network"] = net.describe()
    width = max(len(k) for k in info)
    for k, v in info.items():
        print(f"{k:<{width}} : {v}")
    missing = [k for k, v in info.items() if v == "NOT installed" and k != "tkinter (GUI)"]
    problems = 0
    if missing:
        problems += 1
        print("\nMissing Python packages: " + ", ".join(m.split(" ")[0] for m in missing)
              + "\n  Fix: pip install -e \".[dev]\"   (from the project folder, with the virtual "
              "environment active)\n  or:  pip install " + " ".join(m.split(" ")[0] for m in missing))
    if info["tkinter (GUI)"] == "NOT installed":
        print("\ntkinter is not available, so 'cybersweeper gui' will not start. Debian/Ubuntu: "
              "sudo apt install python3-tk (Windows/macOS: reinstall Python with the tcl/tk option).")
    if info["nmap binary"] != "found":
        print("\nnmap is not installed. The socket engine will be used. Install nmap for -sV "
              "accuracy:\n  Windows : https://nmap.org/download.html (installer includes Npcap)"
              "\n  Debian  : sudo apt install nmap\n  Fedora  : sudo dnf install nmap"
              "\n  macOS   : brew install nmap")
    if not problems:
        print("\nAll required Python packages are present.")
    return 1 if problems else 0


def cmd_discover(args) -> int:
    target = args.target or _auto_target("discover")
    if target is None:
        return 2
    ips = utils.parse_targets(target, max_hosts=args.max_hosts)
    print(f"Discovering hosts in {target} ({len(ips)} addresses) ...")
    progress = ConsoleProgress(not args.quiet)
    hosts, used = discovery.discover_hosts(
        ips, method=args.method, timeout=args.timeout, threads=args.threads,
        resolve_names=not args.no_dns,
        progress=lambda d, t, m: progress("discovery", d, t, m))
    progress("done", 1, 1, f"{len(hosts)} host(s) up via {used}")
    rows = [[h.ip, h.hostname, h.mac, h.vendor] for h in hosts]
    print(report._table(["IP", "HOSTNAME", "MAC", "VENDOR"], rows))
    return 0


def _options_from_args(args) -> ScanOptions:
    return ScanOptions(
        target=args.target, ports=args.ports, method=args.method,
        discover=not args.no_discovery, discovery_method=args.discovery,
        service_detection=not args.no_service, cve_lookup=args.cve,
        timeout=args.timeout, threads=args.threads, max_hosts=args.max_hosts,
    )


def _export(result: ScanResult, args, flt: Optional[report.ReportFilter] = None) -> None:
    if getattr(args, "csv", None):
        print(f"CSV written to {storage.export_csv(result, args.csv)}")
    if getattr(args, "json", None):
        print(f"JSON written to {storage.export_json(result, args.json)}")
    if getattr(args, "html", None):
        Path(args.html).write_text(report.render_html(result, flt), encoding="utf-8")
        print(f"HTML report written to {args.html}")
    for fmt in ("pdf", "docx"):
        target = getattr(args, fmt, None)
        if target:
            try:
                techreport.write(result, fmt, target, flt, title=args.title, organisation=args.org)
                print(f"Technical report ({fmt.upper()}) written to {target}")
            except RuntimeError as exc:
                print(f"error: {exc}", file=sys.stderr)


def cmd_scan(args) -> int:
    auto_net = None
    if not args.target:
        args.target = _auto_target("scan")
        if args.target is None:
            return 2
        auto_net = _auto_target.last  # type: ignore[attr-defined]
    opts = _options_from_args(args)
    if opts.method == "nmap" and not (utils.nmap_available() and utils.python_nmap_available()):
        print("error: --method nmap requested but nmap/python-nmap is not available. "
              "Run 'cybersweeper check' for install hints.", file=sys.stderr)
        return 2
    progress = ConsoleProgress(not args.quiet)
    engine = ScanEngine(opts, progress=progress)
    try:
        result = engine.run()
    except KeyboardInterrupt:
        engine.cancel()
        print("\nScan cancelled.", file=sys.stderr)
        return 130
    except (utils.TargetError, utils.PortError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    if auto_net is not None:
        result.notes.insert(0, f"target auto-detected: {auto_net.describe()}")
    if not args.no_save:
        with _open_db(args) as db:
            db.save_scan(result)
    flt = report.ReportFilter(states=[] if args.all_states else ["open"])
    print(report.render_text(result, flt))
    if result.scan_id:
        print(f"Saved as scan #{result.scan_id}. Re-render later with: cybersweeper report {result.scan_id}")
    _export(result, args, flt)
    return 0


def _filter_from_args(args) -> report.ReportFilter:
    ports: list[int] = []
    for p in args.port:
        ports.extend(utils.parse_ports(p))
    return report.ReportFilter(
        hosts=args.host, ports=ports, services=args.service,
        states=args.state or ["open"], min_severity=args.min_severity,
        only_vulnerable=args.vulnerable, live_only=not args.include_down, sort_by=args.sort,
    )


def cmd_report(args) -> int:
    with _open_db(args) as db:
        scan_id = args.scan_id or db.latest_scan_id()
        if scan_id is None:
            print("No scans stored yet. Run 'cybersweeper scan <target>' first.", file=sys.stderr)
            return 1
        result = db.load_scan(scan_id)
    if result is None:
        print(f"error: scan #{scan_id} not found", file=sys.stderr)
        return 1
    flt = _filter_from_args(args)

    if args.format == "csv":
        target = args.output or f"cybersweeper_scan_{scan_id}.csv"
        filtered = ScanResult(options=result.options, started_at=result.started_at,
                              finished_at=result.finished_at, hosts=flt.apply(result),
                              engine=result.engine, scan_id=result.scan_id)
        storage.export_csv(filtered, target, open_only=flt.states == ["open"])
        print(f"CSV written to {target}")
        return 0
    if args.format in ("pdf", "docx"):
        target = args.output or f"cybersweeper_scan_{scan_id}.{args.format}"
        try:
            techreport.write(result, args.format, target, flt, title=args.title, organisation=args.org)
        except RuntimeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        print(f"Technical report ({args.format.upper()}) written to {target}")
        return 0
    if args.format == "json":
        text = __import__("json").dumps(result.to_dict(), indent=2)
    else:
        text = report.render(result, args.format, flt)
    if args.output:
        Path(args.output).write_text(text, encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(text)
    return 0


def cmd_history(args) -> int:
    with _open_db(args) as db:
        scans = db.list_scans(limit=args.limit)
        total = db.count_scans()
    if not scans:
        print("No scans stored yet.")
        return 0
    rows = [[s["id"], s["started_at"].replace("T", " "), s["target"], s["ports_spec"], s["engine"],
             s["hosts_up"], s["open_ports"], s["vulns"], f"{s['duration'] or 0:.1f}s"] for s in scans]

    print(report._table(["ID", "STARTED", "TARGET", "PORTS", "ENGINE", "HOSTS", "OPEN", "FINDINGS", "TIME"], rows))
    return 0
  # Printing Stops at the limit reads as "this is everything you have".
    if total> len(scans):
        print(f"Showing the {len(scans)} most recent of {total} stored scans - use -n 0 to list them all.")
        return 0

def cmd_delete(args) -> int:
    with _open_db(args) as db:
        ok = db.delete_scan(args.scan_id)
    print(f"Scan #{args.scan_id} deleted." if ok else f"Scan #{args.scan_id} not found.")
    return 0 if ok else 1


def cmd_gui(args) -> int:
    try:
        from cybersweeper.gui import launch
    except ImportError as exc:  # tkinter missing
        print(f"error: the GUI needs tkinter ({exc}). On Debian/Ubuntu: sudo apt install python3-tk",
              file=sys.stderr)
        return 1
    launch(db_path=args.db)
    return 0


COMMANDS = {
    "check": cmd_check, "network": cmd_network, "discover": cmd_discover, "scan": cmd_scan, "report": cmd_report,
    "history": cmd_history, "delete": cmd_delete, "gui": cmd_gui,
}


def main(argv: Optional[list[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    utils.setup_logging(verbose=args.verbose, quiet=args.quiet)
    if not args.no_banner and not args.quiet and args.command in ("scan", "discover"):
        print(config.BANNER)
        print(f"v{__version__} - {config.LEGAL_NOTICE}\n")
    try:
        return COMMANDS[args.command](args)
    except (utils.TargetError, utils.PortError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())

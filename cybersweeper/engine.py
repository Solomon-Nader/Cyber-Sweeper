# The scan engine ties discovery, port scanning, service identification and
# vulnerability assessment together into one pipeline.
#
# Both the CLI and the GUI drive ScanEngine; they only differ in how
# they display progress and results.

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from datetime import datetime
from typing import Optional

from cybersweeper import config, discovery, portscan, utils, vulns
from cybersweeper.models import Host, ScanOptions, ScanResult

log = logging.getLogger("cybersweeper.engine")

# (phase, done, total, message)
ProgressCallback = Callable[[str, int, int, str], None]


# Run a complete scan described by ScanOptions.
class ScanEngine:
    def __init__(self, options: ScanOptions, progress: Optional[ProgressCallback] = None,
                 nvd_client: Optional[vulns.NVDClient] = None) -> None:
        self.options = options
        self.progress = progress or (lambda *_: None)
        self.cancel_event = threading.Event()
        self._nvd_client = nvd_client

    # ------------------------------------------------------------------ #

    # Ask a running scan to stop as soon as possible.
    def cancel(self) -> None:
        self.cancel_event.set()

    @property
    def cancelled(self) -> bool:
        return self.cancel_event.is_set()

    # ------------------------------------------------------------------ #

    def run(self) -> ScanResult:
        opts = self.options
        result = ScanResult(options=opts, started_at=datetime.now())

        # 1. Expand targets and ports -----------------------------------
        ips = utils.parse_targets(opts.target, max_hosts=opts.max_hosts)
        ports = utils.parse_ports(opts.ports)
        log.info("targets: %d host(s), %d port(s)", len(ips), len(ports))
        self.progress("prepare", 0, len(ips), f"{len(ips)} host(s), {len(ports)} port(s)")

        # 2. Host discovery ---------------------------------------------
        if opts.discover and not (opts.skip_discovery_for_single and len(ips) == 1):
            hosts, used = discovery.discover_hosts(
                ips, method=opts.discovery_method, timeout=opts.timeout, threads=opts.threads,
                progress=lambda d, t, msg: self.progress("discovery", d, t, msg),
            )
            result.notes.append(f"discovery via {used}: {len(hosts)}/{len(ips)} hosts up")
        else:
            hosts = [Host(ip=ip, is_up=True, discovery_method="assumed") for ip in ips]
            if len(ips) == 1:
                hosts[0].hostname = discovery.reverse_dns(ips[0])
        if self.cancelled:
            return self._finish(result, hosts, "cancelled during discovery")

        # 3. Port scan + service identification --------------------------
        scanner = portscan.make_scanner(
            opts.method, timeout=opts.timeout, threads=opts.threads,
            service_detection=opts.service_detection, cancel_event=self.cancel_event,
        )
        result.engine = scanner.name
        if opts.method == "auto":
            result.notes.append(f"scan engine: {scanner.name}")
        total_hosts = len(hosts)
        for index, host in enumerate(hosts, start=1):
            if self.cancelled:
                break
            self.progress("portscan", index - 1, total_hosts, f"scanning {host.ip}")
            try:
                scanner.scan_host(
                    host, ports,
                    progress=lambda d, t, msg, i=index: self.progress(
                        "ports", d, t, f"[{i}/{total_hosts}] {msg}"),
                )
            except portscan.ScanCancelled:
                break
            except RuntimeError as exc:
                # nmap died - degrade to the socket engine for the rest.
                log.warning("%s; switching to socket scanner", exc)
                result.notes.append(f"nmap error on {host.ip}: {exc}; used socket scanner")
                scanner = portscan.SocketScanner(timeout=opts.timeout, threads=opts.threads,
                                                 grab_banners=opts.service_detection,
                                                 cancel_event=self.cancel_event)
                result.engine = "socket"
                scanner.scan_host(host, ports)
            if host.open_ports and not host.is_up:
                host.is_up = True
            self.progress("portscan", index, total_hosts,
                          f"{host.ip}: {len(host.open_ports)} open")

        # 4. Vulnerability assessment ------------------------------------
        client = None
        if opts.cve_lookup and not self.cancelled:
            client = self._nvd_client or vulns.NVDClient()
        for host in hosts:
            if self.cancelled:
                break
            vulns.assess_host(host, client=client,
                              progress=lambda msg: self.progress("vulns", 0, 0, msg))
        if client is not None and client.errors:
            result.notes.extend(client.errors[:5])

        return self._finish(result, hosts, "cancelled by user" if self.cancelled else "")

    # ------------------------------------------------------------------ #

    def _finish(self, result: ScanResult, hosts: list[Host], note: str) -> ScanResult:
        result.hosts = hosts
        result.finished_at = datetime.now()
        if note:
            result.notes.append(note)
        self.progress("done", 1, 1, f"finished in {utils.human_duration(result.duration)}")
        return result


# Convenience wrapper: quick_scan("192.168.1.1", "common").
def quick_scan(target: str, ports: str = "top100", **kwargs) -> ScanResult:
    opts = ScanOptions(target=target, ports=ports, **kwargs)
    return ScanEngine(opts).run()


# Summarise the tool's runtime environment for the check command.
def environment_report() -> dict[str, str]:
    import platform
    import sys

    def has(module: str) -> str:
        try:
            __import__(module)
        except ImportError:
            return "NOT installed"
        return "installed"

    return {
        "python": sys.version.split()[0],
        "platform": f"{platform.system()} {platform.release()}",
        "nmap binary": "found" if utils.nmap_available() else "NOT found",
        "python-nmap": "installed" if utils.python_nmap_available() else "NOT installed",
        "requests (NVD lookups)": has("requests"),
        "reportlab (PDF reports)": has("reportlab"),
        "python-docx (Word reports)": has("docx"),
        "tkinter (GUI)": has("tkinter"),
        "local ip": utils.local_ip(),
        "data directory": str(config.data_dir()),
        "nvd api key": "set" if config.NVD_API_KEY_ENV in __import__("os").environ else "not set",
    }

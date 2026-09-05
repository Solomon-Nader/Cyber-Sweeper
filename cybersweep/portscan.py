"""Port scanning engines.

* :class:`SocketScanner` - a multithreaded TCP connect scanner built on the
  standard ``socket`` module. It works on every platform without privileges
  and optionally grabs service banners.
* :class:`NmapScanner` - a thin wrapper around ``python-nmap`` that runs
  ``nmap -sV`` for more accurate port states, service and version detection,
  and (where permitted) OS guessing.

Both engines return the same :class:`~cybersweep.models.Host` objects so the
rest of the application does not care which one produced the data.
"""

from __future__ import annotations

import logging
import socket
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from cybersweep import config, services
from cybersweep.models import Host, Port
from cybersweep.utils import nmap_available, ports_to_spec, python_nmap_available

log = logging.getLogger("cybersweep.portscan")

ProgressCallback = Callable[[int, int, str], None]


class ScanCancelled(Exception):
    """Raised inside worker threads when the user cancels the scan."""


# --------------------------------------------------------------------------- #
# Socket scanner
# --------------------------------------------------------------------------- #


class SocketScanner:
    """TCP connect scanner using ``socket.connect_ex`` in a thread pool."""

    name = "socket"

    def __init__(self, timeout: float = config.DEFAULT_CONNECT_TIMEOUT,
                 threads: int = config.DEFAULT_THREADS, grab_banners: bool = True,
                 cancel_event: Optional[threading.Event] = None) -> None:
        self.timeout = timeout
        self.threads = max(1, threads)
        self.grab_banners = grab_banners
        self.cancel_event = cancel_event or threading.Event()

    # -- single port ------------------------------------------------------- #

    def probe_port(self, ip: str, port: int) -> Port:
        """Probe one TCP port and return a :class:`Port` with its state."""
        if self.cancel_event.is_set():
            raise ScanCancelled()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(self.timeout)
        try:
            code = s.connect_ex((ip, port))
        except OSError:
            code = -1
        if code == 0:
            banner = ""
            if self.grab_banners:
                banner = services.grab_banner(s, port, timeout=min(self.timeout * 2, 3.0))
            s.close()
            p = Port(number=port, state="open", banner=banner)
            services.identify(p)
            return p
        s.close()
        # ECONNREFUSED -> closed (host answered); anything else -> filtered.
        state = "closed" if code in (111, 10061, 61) else "filtered"
        return Port(number=port, state=state, service=config.WELL_KNOWN_SERVICES.get(port, ""))

    # -- whole host -------------------------------------------------------- #

    def scan_host(self, host: Host, ports: list[int],
                  progress: Optional[ProgressCallback] = None) -> Host:
        """Scan *ports* on *host*, filling ``host.ports`` with the results."""
        results: list[Port] = []
        done = 0
        total = len(ports)
        with ThreadPoolExecutor(max_workers=min(self.threads, total or 1)) as pool:
            futures = {pool.submit(self.probe_port, host.ip, p): p for p in ports}
            try:
                for fut in as_completed(futures):
                    done += 1
                    try:
                        results.append(fut.result())
                    except ScanCancelled:
                        raise
                    except Exception as exc:  # pragma: no cover - defensive
                        log.debug("probe %s:%s failed: %s", host.ip, futures[fut], exc)
                    if progress:
                        progress(done, total, f"{host.ip}:{futures[fut]}")
            except ScanCancelled:
                pool.shutdown(wait=False, cancel_futures=True)
                raise
        results.sort(key=lambda p: p.number)
        # Keep open ports plus "closed" ones only when the list is small; a
        # scan of 65k ports should not store 65k closed rows.
        if total > 200:
            results = [p for p in results if p.is_open]
        host.ports = results
        if not host.discovery_method and host.ports:
            host.discovery_method = "portscan"
        return host


# --------------------------------------------------------------------------- #
# nmap scanner
# --------------------------------------------------------------------------- #


class NmapScanner:
    """Run nmap through ``python-nmap`` and convert the output to our model."""

    name = "nmap"

    def __init__(self, service_detection: bool = True, os_detection: bool = False,
                 timing: str = "T4", extra_args: str = "") -> None:
        if not python_nmap_available():
            raise RuntimeError("python-nmap is not installed (pip install python-nmap)")
        if not nmap_available():
            raise RuntimeError("the nmap program is not installed or not on PATH")
        self.service_detection = service_detection
        self.os_detection = os_detection
        self.timing = timing
        self.extra_args = extra_args

    def build_arguments(self) -> str:
        args = [f"-{self.timing}", "-Pn", "-n"]
        if self.service_detection:
            args.append("-sV")
        if self.os_detection:
            args.append("-O")
        if self.extra_args:
            args.append(self.extra_args)
        return " ".join(args)

    def scan_host(self, host: Host, ports: list[int],
                  progress: Optional[ProgressCallback] = None) -> Host:
        import nmap

        scanner = nmap.PortScanner()
        port_spec = ports_to_spec(ports)
        log.debug("nmap %s -p %s %s", self.build_arguments(), port_spec, host.ip)
        try:
            scanner.scan(hosts=host.ip, ports=port_spec, arguments=self.build_arguments())
        except nmap.PortScannerError as exc:
            raise RuntimeError(f"nmap failed: {exc}") from exc

        if host.ip not in scanner.all_hosts():
            host.ports = []
            if progress:
                progress(len(ports), len(ports), host.ip)
            return host

        info = scanner[host.ip]
        host.is_up = info.state() == "up"
        addresses = info.get("addresses", {})
        mac = addresses.get("mac", "")
        if mac:
            host.mac = mac
            host.vendor = info.get("vendor", {}).get(mac, "") or host.vendor
        names = info.get("hostnames", [])
        if names and names[0].get("name"):
            host.hostname = host.hostname or names[0]["name"]
        if self.os_detection:
            matches = info.get("osmatch", [])
            if matches:
                host.os_guess = f"{matches[0]['name']} ({matches[0]['accuracy']}%)"

        results: list[Port] = []
        for proto in info.all_protocols():
            for number, data in info[proto].items():
                state = data.get("state", "")
                if state not in ("open", "closed", "filtered", "open|filtered"):
                    continue
                p = Port(
                    number=int(number), protocol=proto, state=state,
                    service=data.get("name", ""), product=data.get("product", ""),
                    version=data.get("version", ""),
                    banner=" ".join(x for x in (data.get("extrainfo", ""), data.get("cpe", "")) if x),
                )
                if p.is_open and not p.product:
                    services.identify(p)  # fill from well-known table
                results.append(p)
        results.sort(key=lambda p: p.number)
        if len(ports) > 200:
            results = [p for p in results if p.is_open]
        host.ports = results
        if progress:
            progress(len(ports), len(ports), host.ip)
        return host


# --------------------------------------------------------------------------- #
# Factory
# --------------------------------------------------------------------------- #


def make_scanner(method: str = "auto", timeout: float = config.DEFAULT_CONNECT_TIMEOUT,
                 threads: int = config.DEFAULT_THREADS, service_detection: bool = True,
                 cancel_event: Optional[threading.Event] = None):
    """Return the scanner requested by *method* (``auto``/``socket``/``nmap``).

    ``auto`` prefers nmap when it is installed and silently falls back to the
    socket engine otherwise. Asking for ``nmap`` explicitly when it is missing
    raises ``RuntimeError`` so the user knows why.
    """
    method = (method or "auto").lower()
    if method == "nmap":
        return NmapScanner(service_detection=service_detection)
    if method == "auto" and nmap_available() and python_nmap_available():
        try:
            return NmapScanner(service_detection=service_detection)
        except RuntimeError as exc:  # pragma: no cover
            log.warning("%s; using socket scanner", exc)
    if method not in ("auto", "socket"):
        raise ValueError(f"unknown scan method '{method}' (expected auto, socket or nmap)")
    return SocketScanner(timeout=timeout, threads=threads, grab_banners=service_detection,
                         cancel_event=cancel_event)

# Host discovery: find which addresses in a target range are alive.
#
# Three techniques are available and can be combined:
#
# * tcp - a TCP connect probe against a handful of common ports using the
#   socket module. A host that answers with SYN/ACK *or* RST is alive. Works
#   everywhere without privileges and is the default fallback.
# * ping - the operating system's ping command (ICMP echo). Cross
#   platform (Windows / Linux / macOS flags are handled).
# * arp - nmap -sn which, on a local Ethernet segment, uses ARP and also
#   returns MAC addresses and vendors. Requires nmap (and privileges for ARP).
#
# discover_hosts picks the best available technique when method="auto".

from __future__ import annotations

import logging
import socket
import subprocess
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional

from cybersweeper import config
from cybersweeper.models import Host
from cybersweeper.utils import is_windows, nmap_available, python_nmap_available

log = logging.getLogger("cybersweeper.discovery")

ProgressCallback = Callable[[int, int, str], None]


# --------------------------------------------------------------------------- #
# Individual probes
# --------------------------------------------------------------------------- #


# Return True if *ip* answers a TCP connection attempt on any probe port.
#
# connect_ex returns 0 for an open port and ECONNREFUSED (111 on
# Linux, 10061 on Windows) for a closed-but-alive port; both prove the host
# exists. A timeout or "host unreachable" proves nothing, so we try the next
# port.
def tcp_probe(ip: str, ports: Iterable[int] = config.DISCOVERY_PROBE_PORTS,
              timeout: float = config.DEFAULT_CONNECT_TIMEOUT) -> bool:
    refused = {111, 10061, 61}  # Linux, Windows, macOS ECONNREFUSED
    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            code = s.connect_ex((ip, port))
        except OSError:
            code = -1
        finally:
            s.close()
        if code == 0 or code in refused:
            return True
    return False


# Return True if the host answers a single ICMP echo request.
def ping_probe(ip: str, timeout_ms: int = config.DEFAULT_PING_TIMEOUT_MS) -> bool:
    if is_windows():
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=timeout_ms / 1000 + 2, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    if proc.returncode != 0:
        return False
    # Windows ping exits 0 even for "Destination host unreachable"; re-run with
    # captured output in that case would double the cost, so we accept the
    # small false-positive risk only there and let the port scan sort it out.
    return True


# Best-effort reverse DNS lookup.
def reverse_dns(ip: str, timeout: float = 1.0) -> str:
    old = socket.getdefaulttimeout()
    socket.setdefaulttimeout(timeout)
    try:
        return socket.gethostbyaddr(ip)[0]
    except (OSError, socket.herror):
        return ""
    finally:
        socket.setdefaulttimeout(old)


# --------------------------------------------------------------------------- #
# Bulk discovery
# --------------------------------------------------------------------------- #


def _sweep(ips: list[str], probe: Callable[[str], bool], method: str, threads: int,
           progress: Optional[ProgressCallback]) -> list[Host]:
    hosts: list[Host] = []
    total = len(ips)
    done = 0
    with ThreadPoolExecutor(max_workers=max(1, min(threads, total or 1))) as pool:
        futures = {pool.submit(probe, ip): ip for ip in ips}
        for fut in as_completed(futures):
            ip = futures[fut]
            done += 1
            try:
                alive = fut.result()
            except Exception as exc:  # pragma: no cover - defensive
                log.debug("probe failed for %s: %s", ip, exc)
                alive = False
            if alive:
                hosts.append(Host(ip=ip, is_up=True, discovery_method=method))
            if progress:
                progress(done, total, ip)
    hosts.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return hosts


def discover_tcp(ips: list[str], timeout: float = config.DEFAULT_CONNECT_TIMEOUT,
                 threads: int = config.DEFAULT_THREADS,
                 progress: Optional[ProgressCallback] = None) -> list[Host]:
    return _sweep(ips, lambda ip: tcp_probe(ip, timeout=timeout), "tcp", threads, progress)


def discover_ping(ips: list[str], timeout_ms: int = config.DEFAULT_PING_TIMEOUT_MS,
                  threads: int = 50, progress: Optional[ProgressCallback] = None) -> list[Host]:
    return _sweep(ips, lambda ip: ping_probe(ip, timeout_ms), "ping", threads, progress)


# Use nmap -sn for discovery. Returns MAC/vendor where nmap reports them.
def discover_arp(ips: list[str], progress: Optional[ProgressCallback] = None) -> list[Host]:
    import nmap  # imported lazily so the rest of the module works without it

    scanner = nmap.PortScanner()
    target = " ".join(ips)
    scanner.scan(hosts=target, arguments="-sn -n")
    hosts: list[Host] = []
    for ip in scanner.all_hosts():
        info = scanner[ip]
        if info.state() != "up":
            continue
        addresses = info.get("addresses", {})
        vendor = info.get("vendor", {})
        mac = addresses.get("mac", "")
        hosts.append(Host(
            ip=ip, is_up=True, discovery_method="arp/nmap",
            mac=mac, vendor=vendor.get(mac, "") if mac else "",
        ))
    if progress:
        progress(len(ips), len(ips), "nmap")
    hosts.sort(key=lambda h: tuple(int(o) for o in h.ip.split(".")))
    return hosts


# Discover live hosts among *ips*.
#
# Returns (hosts, method_used). With method="auto" nmap is used when
# it is installed, otherwise a combined TCP + ping sweep. Hosts found by any
# technique are merged (a host is alive if any probe says so).
def discover_hosts(ips: list[str], method: str = "auto",
                   timeout: float = config.DEFAULT_CONNECT_TIMEOUT,
                   threads: int = config.DEFAULT_THREADS,
                   resolve_names: bool = True,
                   progress: Optional[ProgressCallback] = None) -> tuple[list[Host], str]:
    method = (method or "auto").lower()
    if method == "arp" and not (nmap_available() and python_nmap_available()):
        log.warning("nmap is not available; falling back to TCP discovery")
        method = "tcp"

    if method == "auto":
        method = "arp" if (nmap_available() and python_nmap_available()) else "combined"

    if method == "arp":
        try:
            hosts = discover_arp(ips, progress)
            used = "arp/nmap"
        except Exception as exc:  # nmap failed (permissions, parsing...)
            log.warning("nmap discovery failed (%s); falling back to TCP/ping", exc)
            method = "combined"

    if method == "tcp":
        hosts, used = discover_tcp(ips, timeout, threads, progress), "tcp"
    elif method == "ping":
        hosts, used = discover_ping(ips, int(timeout * 1000), progress=progress), "ping"
    elif method == "combined":
        tcp_hosts = {h.ip: h for h in discover_tcp(ips, timeout, threads, progress)}
        for h in discover_ping(ips, int(timeout * 1000)):
            tcp_hosts.setdefault(h.ip, h)
        hosts = sorted(tcp_hosts.values(), key=lambda h: tuple(int(o) for o in h.ip.split(".")))
        used = "tcp+ping"

    if resolve_names and hosts:
        with ThreadPoolExecutor(max_workers=min(20, len(hosts))) as pool:
            names = list(pool.map(lambda h: reverse_dns(h.ip), hosts))
        for h, name in zip(hosts, names):
            h.hostname = h.hostname or name

    log.info("discovery (%s): %d/%d hosts up", used, len(hosts), len(ips))
    return hosts, used

"""Helper functions shared across CyberSweep: target/port parsing, validation,
platform helpers and logging setup."""

from __future__ import annotations

import ipaddress
import logging
import platform
import shutil
import socket
import sys
from collections.abc import Iterable

from cybersweep import config

log = logging.getLogger("cybersweep")


class TargetError(ValueError):
    """Raised when a target specification cannot be understood."""


class PortError(ValueError):
    """Raised when a port specification cannot be understood."""


# --------------------------------------------------------------------------- #
# Logging
# --------------------------------------------------------------------------- #


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    """Configure the root ``cybersweep`` logger for console output."""
    level = logging.DEBUG if verbose else logging.WARNING if quiet else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
    log.handlers.clear()
    log.addHandler(handler)
    log.setLevel(level)
    log.propagate = False


# --------------------------------------------------------------------------- #
# Platform helpers
# --------------------------------------------------------------------------- #


def is_windows() -> bool:
    return platform.system().lower().startswith("win")


def nmap_available() -> bool:
    """Return True when the nmap binary can be found on PATH."""
    return shutil.which("nmap") is not None


def python_nmap_available() -> bool:
    """Return True when the ``python-nmap`` library can be imported."""
    try:
        import nmap  # noqa: F401
    except ImportError:
        return False
    return True


def local_ip() -> str:
    """Best-effort detection of the primary local IPv4 address."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # No packets are actually sent for a UDP "connect".
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def local_network_cidr(prefix: int = 24) -> str:
    """Guess the local network in CIDR notation (defaults to a /24)."""
    ip = local_ip()
    net = ipaddress.ip_network(f"{ip}/{prefix}", strict=False)
    return str(net)


# --------------------------------------------------------------------------- #
# Target parsing
# --------------------------------------------------------------------------- #


def resolve_hostname(name: str) -> str:
    """Resolve a DNS name to an IPv4 address, raising TargetError on failure."""
    try:
        return socket.gethostbyname(name)
    except socket.gaierror as exc:
        raise TargetError(f"cannot resolve hostname '{name}': {exc}") from exc


def parse_targets(spec: str, max_hosts: int = config.MAX_HOSTS_WITHOUT_CONFIRMATION) -> list[str]:
    """Expand a target specification into a list of IPv4 addresses.

    Supported forms (comma separated, whitespace ignored)::

        192.168.1.10                single address
        192.168.1.0/24              CIDR network (network/broadcast excluded)
        192.168.1.10-20             last-octet range
        192.168.1.10-192.168.1.20   full range
        example.com                 hostname (resolved via DNS)
        localhost

    The list preserves order and contains no duplicates. ``TargetError`` is
    raised for malformed input or when the expansion exceeds ``max_hosts``.
    """
    if not spec or not spec.strip():
        raise TargetError("target specification is empty")

    result: list[str] = []
    seen: set[str] = set()

    def add(ip: str) -> None:
        if ip not in seen:
            seen.add(ip)
            result.append(ip)

    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue

        # CIDR
        if "/" in item:
            try:
                net = ipaddress.ip_network(item, strict=False)
            except ValueError as exc:
                raise TargetError(f"invalid network '{item}': {exc}") from exc
            if net.version != 4:
                raise TargetError("only IPv4 networks are supported")
            hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
            if len(result) + len(hosts) > max_hosts:
                raise TargetError(
                    f"'{item}' expands to {len(hosts)} hosts; limit is {max_hosts}. "
                    "Narrow the range or raise --max-hosts."
                )
            for h in hosts:
                add(str(h))
            continue

        # Range
        if "-" in item and item.replace(".", "").replace("-", "").isdigit():
            start_s, end_s = item.split("-", 1)
            try:
                start = ipaddress.IPv4Address(start_s)
                if "." in end_s:
                    end = ipaddress.IPv4Address(end_s)
                else:
                    last = int(end_s)
                    if not 0 <= last <= 255:
                        raise ValueError("last octet out of range")
                    end = ipaddress.IPv4Address(".".join(start_s.split(".")[:3] + [str(last)]))
            except ValueError as exc:
                raise TargetError(f"invalid range '{item}': {exc}") from exc
            if int(end) < int(start):
                raise TargetError(f"range '{item}' ends before it starts")
            count = int(end) - int(start) + 1
            if len(result) + count > max_hosts:
                raise TargetError(f"'{item}' expands to {count} hosts; limit is {max_hosts}.")
            for n in range(int(start), int(end) + 1):
                add(str(ipaddress.IPv4Address(n)))
            continue

        # Plain address
        try:
            addr = ipaddress.ip_address(item)
            if addr.version != 4:
                raise TargetError("only IPv4 addresses are supported")
            add(str(addr))
            continue
        except ValueError:
            pass

        # Hostname
        add(resolve_hostname(item))

    if not result:
        raise TargetError("target specification produced no hosts")
    return result


# --------------------------------------------------------------------------- #
# Port parsing
# --------------------------------------------------------------------------- #


def parse_ports(spec: str | None) -> list[int]:
    """Expand a port specification into a sorted list of unique ports.

    Accepts presets (``common``, ``top100``, ``top1000``, ``all``), single
    ports, ranges (``1-1024``) and comma separated mixes of both. ``None`` or an
    empty string returns the ``top100`` preset.
    """
    if spec is None or not spec.strip():
        return list(config.TOP_100_PORTS)

    key = spec.strip().lower()
    if key in config.PORT_PRESETS:
        return list(config.PORT_PRESETS[key])

    ports: set[int] = set()
    for raw in spec.split(","):
        item = raw.strip()
        if not item:
            continue
        if item.lower() in config.PORT_PRESETS:
            ports.update(config.PORT_PRESETS[item.lower()])
            continue
        if "-" in item:
            a, _, b = item.partition("-")
            try:
                lo, hi = int(a), int(b)
            except ValueError as exc:
                raise PortError(f"invalid port range '{item}'") from exc
            if not (1 <= lo <= hi <= 65535):
                raise PortError(f"port range '{item}' must be within 1-65535")
            ports.update(range(lo, hi + 1))
        else:
            try:
                p = int(item)
            except ValueError as exc:
                raise PortError(f"invalid port '{item}'") from exc
            if not 1 <= p <= 65535:
                raise PortError(f"port {p} is outside 1-65535")
            ports.add(p)
    if not ports:
        raise PortError("port specification produced no ports")
    return sorted(ports)


def ports_to_spec(ports: Iterable[int]) -> str:
    """Compress a list of ports back into an nmap-style specification."""
    ports = sorted(set(ports))
    if not ports:
        return ""
    chunks: list[str] = []
    start = prev = ports[0]
    for p in ports[1:]:
        if p == prev + 1:
            prev = p
            continue
        chunks.append(str(start) if start == prev else f"{start}-{prev}")
        start = prev = p
    chunks.append(str(start) if start == prev else f"{start}-{prev}")
    return ",".join(chunks)


def human_duration(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes, sec = divmod(int(seconds), 60)
    if minutes < 60:
        return f"{minutes}m {sec}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"

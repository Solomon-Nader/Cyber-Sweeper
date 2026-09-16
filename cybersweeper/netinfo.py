# Detect the network the machine is currently connected to.
#
# Cyber Sweeper uses this to answer, without any user input: *am I connected?*,
# *over Wi-Fi or a cable?*, *to which SSID?*, *what is my address, subnet and
# gateway?* - and then to propose (or automatically use) that subnet as the scan
# target.
#
# Platform strategy (no third-party packages):
#
# * Windows - a short PowerShell snippet built on the Get-Net* cmdlets,
#   emitting JSON. Property names are language-invariant, so this works on
#   Arabic, French or English Windows alike (unlike parsing ipconfig).
#   Get-NetConnectionProfile returns the Wi-Fi SSID as the profile name and
#   Get-NetAdapter tells wireless (Native 802.11) from wired (802.3).
# * Linux - ip -j route / ip -j addr (iproute2 JSON), the
#   /sys/class/net/<dev>/wireless marker, and iwgetid/nmcli/iw
#   for the SSID.
# * macOS - route, ifconfig and networksetup (best effort).
#
# Whatever fails, the module falls back to the classic "UDP connect" trick for
# the primary IPv4 address and assumes a /24, so callers always get an answer.

from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import shutil
import socket
import subprocess
from dataclasses import asdict, dataclass, field
from typing import Any, Optional

log = logging.getLogger("cybersweeper.netinfo")

_TIMEOUT = 8  # seconds per external command


# What we know about the network the machine is on.
@dataclass
class NetworkInfo:
    connected: bool = False
    kind: str = "unknown"  # wifi / ethernet / unknown
    ssid: str = ""
    interface: str = ""
    ip: str = ""
    prefix: int = 24
    gateway: str = ""
    mac: str = ""
    method: str = ""  # which detection path produced the result
    notes: list[str] = field(default_factory=list)

    # The network in CIDR form, e.g. 192.168.1.0/24 (empty if offline).
    @property
    def cidr(self) -> str:
        if not self.ip:
            return ""
        try:
            return str(ipaddress.ip_network(f"{self.ip}/{self.prefix}", strict=False))
        except ValueError:
            return ""

    @property
    def host_count(self) -> int:
        if not self.cidr:
            return 0
        return max(0, ipaddress.ip_network(self.cidr).num_addresses - 2)

    # One-line human summary used by the CLI and GUI.
    def describe(self) -> str:
        if not self.connected:
            return "Not connected to any network"
        kind = {"wifi": "Wi-Fi", "ethernet": "Ethernet"}.get(self.kind, "network")
        name = f" '{self.ssid}'" if self.ssid else ""
        iface = f" via {self.interface}" if self.interface and self.interface != self.ssid else ""
        gw = f", gateway {self.gateway}" if self.gateway else ""
        return f"Connected to {kind}{name}{iface} - {self.ip}/{self.prefix} ({self.cidr}, {self.host_count} hosts{gw})"

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["cidr"] = self.cidr
        return d


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #


# Run a command and return stdout ('' on any failure).
def _run(cmd: list[str], timeout: int = _TIMEOUT) -> str:
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False,
                              encoding="utf-8", errors="replace")
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("command %s failed: %s", cmd[0], exc)
        return ""
    return proc.stdout or ""


# The IPv4 address the OS would use to reach the Internet ('' if none).
def primary_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))  # no packet is sent for UDP connect
        ip = s.getsockname()[0]
    except OSError:
        return ""
    finally:
        s.close()
    return "" if ip.startswith("127.") else ip


def _is_private_usable(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (addr.is_loopback or addr.is_link_local or addr.is_unspecified)


# --------------------------------------------------------------------------- #
# Windows
# --------------------------------------------------------------------------- #

_PS_SCRIPT = r"""
$ErrorActionPreference = 'SilentlyContinue'
$out = @()
foreach ($c in Get-NetIPConfiguration) {
  if (-not $c.IPv4DefaultGateway) { continue }
  $a  = Get-NetAdapter -InterfaceIndex $c.InterfaceIndex
  $ip = Get-NetIPAddress -InterfaceIndex $c.InterfaceIndex -AddressFamily IPv4 | Select-Object -First 1
  $p  = Get-NetConnectionProfile -InterfaceIndex $c.InterfaceIndex
  $out += [pscustomobject]@{
    alias   = $c.InterfaceAlias
    ip      = $ip.IPAddress
    prefix  = $ip.PrefixLength
    gateway = $c.IPv4DefaultGateway.NextHop
    mac     = $a.MacAddress
    media   = $a.PhysicalMediaType
    desc    = $a.InterfaceDescription
    profile = $p.Name
    status  = $a.Status
  }
}
ConvertTo-Json -InputObject @($out) -Compress
"""


# Turn the PowerShell JSON into a NetworkInfo (pure function, testable).
def parse_windows_json(text: str, local_ip: str = "") -> Optional[NetworkInfo]:
    text = text.strip()
    if not text:
        return None
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if isinstance(data, dict):
        data = [data]
    entries = [e for e in data if isinstance(e, dict) and e.get("ip")]
    if not entries:
        return None
    chosen = next((e for e in entries if e.get("ip") == local_ip), None) or entries[0]
    media = (chosen.get("media") or "").lower()
    desc = (chosen.get("desc") or "").lower()
    alias = chosen.get("alias") or ""
    if "802.11" in media or "wireless" in desc or "wi-fi" in alias.lower() or "wlan" in alias.lower():
        kind = "wifi"
    elif "802.3" in media or "ethernet" in desc or "ethernet" in alias.lower():
        kind = "ethernet"
    else:
        kind = "unknown"
    try:
        prefix = int(chosen.get("prefix") or 24)
    except (TypeError, ValueError):
        prefix = 24
    return NetworkInfo(
        connected=True, kind=kind, ssid=(chosen.get("profile") or "") if kind == "wifi" else "",
        interface=alias, ip=chosen["ip"], prefix=prefix, gateway=chosen.get("gateway") or "",
        mac=(chosen.get("mac") or "").replace("-", ":"), method="windows/powershell",
    )


def _detect_windows(local_ip: str) -> Optional[NetworkInfo]:
    ps = shutil.which("powershell") or shutil.which("pwsh")
    if not ps:
        return None
    out = _run([ps, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PS_SCRIPT],
               timeout=20)
    info = parse_windows_json(out, local_ip)
    if info and info.kind == "wifi" and not info.ssid:
        # Fallback for the SSID: netsh (may be localised, so best effort only).
        m = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", _run(["netsh", "wlan", "show", "interfaces"]), re.M)
        if m:
            info.ssid = m.group(1)
    return info


# --------------------------------------------------------------------------- #
# Linux
# --------------------------------------------------------------------------- #


# Build a NetworkInfo from ip -j route / ip -j addr output.
def parse_linux(route_json: str, addr_json: str, wireless: bool, ssid: str = "",
                mac: str = "") -> Optional[NetworkInfo]:
    try:
        routes = json.loads(route_json) if route_json.strip() else []
    except ValueError:
        routes = []
    default = next((r for r in routes if r.get("dst") == "default" and r.get("dev")), None)
    if not default:
        return None
    dev = default["dev"]
    ip, prefix = "", 24
    try:
        for entry in json.loads(addr_json) if addr_json.strip() else []:
            for a in entry.get("addr_info", []):
                if a.get("family") == "inet" and a.get("scope") == "global":
                    ip, prefix = a["local"], int(a.get("prefixlen", 24))
                    break
            if ip:
                break
    except (ValueError, KeyError, TypeError):
        pass
    if not ip:
        return None
    return NetworkInfo(connected=True, kind="wifi" if wireless else "ethernet", ssid=ssid if wireless else "",
                       interface=dev, ip=ip, prefix=prefix, gateway=default.get("gateway", ""),
                       mac=mac, method="linux/iproute2")


def _linux_ssid(dev: str) -> str:
    if shutil.which("iwgetid"):
        out = _run(["iwgetid", "-r", dev]).strip()
        if out:
            return out
    if shutil.which("nmcli"):
        for line in _run(["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"]).splitlines():
            if line.startswith("yes:"):
                return line.split(":", 1)[1]
    if shutil.which("iw"):
        m = re.search(r"^\s*SSID:\s*(.+)$", _run(["iw", "dev", dev, "link"]), re.M)
        if m:
            return m.group(1).strip()
    return ""


# Query an interface address via ioctl (SIOCGIFADDR / SIOCGIFNETMASK).
def _linux_ioctl_addr(dev: str, request: int) -> str:
    import fcntl
    import struct

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        packed = struct.pack("256s", dev.encode()[:15])
        return socket.inet_ntoa(fcntl.ioctl(s.fileno(), request, packed)[20:24])
    except OSError:
        return ""
    finally:
        s.close()


# Fallback for minimal systems without iproute2: /proc/net/route + ioctl.
def _detect_linux_proc(local_ip: str) -> Optional[NetworkInfo]:
    try:
        with open("/proc/net/route", encoding="utf-8") as fh:
            lines = fh.read().splitlines()[1:]
    except OSError:
        return None
    dev, gateway = "", ""
    for line in lines:
        parts = line.split()
        if len(parts) >= 3 and parts[1] == "00000000":  # destination 0.0.0.0 = default route
            dev = parts[0]
            gateway = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
            break
    if not dev:
        return None
    ip = _linux_ioctl_addr(dev, 0x8915) or local_ip  # SIOCGIFADDR
    mask = _linux_ioctl_addr(dev, 0x891B)  # SIOCGIFNETMASK
    if not ip:
        return None
    prefix = ipaddress.IPv4Network(f"0.0.0.0/{mask}").prefixlen if mask else 24
    wireless = os.path.isdir(f"/sys/class/net/{dev}/wireless") or os.path.exists(f"/sys/class/net/{dev}/phy80211")
    mac = ""
    try:
        with open(f"/sys/class/net/{dev}/address", encoding="utf-8") as fh:
            mac = fh.read().strip()
    except OSError:
        pass
    return NetworkInfo(connected=True, kind="wifi" if wireless else "ethernet",
                       ssid=_linux_ssid(dev) if wireless else "", interface=dev, ip=ip, prefix=prefix,
                       gateway=gateway, mac=mac, method="linux/procfs")


def _detect_linux(local_ip: str) -> Optional[NetworkInfo]:
    if not shutil.which("ip"):
        return _detect_linux_proc(local_ip)
    route_json = _run(["ip", "-j", "route", "show", "default"])
    try:
        routes = json.loads(route_json) if route_json.strip() else []
    except ValueError:
        return None
    default = next((r for r in routes if r.get("dst") == "default"), None)
    if not default:
        return None
    dev = default.get("dev", "")
    addr_json = _run(["ip", "-j", "-4", "addr", "show", "dev", dev])
    wireless = os.path.isdir(f"/sys/class/net/{dev}/wireless") or os.path.exists(f"/sys/class/net/{dev}/phy80211")
    mac = ""
    try:
        with open(f"/sys/class/net/{dev}/address", encoding="utf-8") as fh:
            mac = fh.read().strip()
    except OSError:
        pass
    ssid = _linux_ssid(dev) if wireless else ""
    return parse_linux(route_json, addr_json, wireless, ssid, mac)


# --------------------------------------------------------------------------- #
# macOS
# --------------------------------------------------------------------------- #


def _detect_macos(local_ip: str) -> Optional[NetworkInfo]:
    route = _run(["route", "-n", "get", "default"])
    gw = re.search(r"gateway:\s*(\S+)", route)
    dev = re.search(r"interface:\s*(\S+)", route)
    if not dev:
        return None
    dev = dev.group(1)
    ifc = _run(["ifconfig", dev])
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+) netmask 0x([0-9a-f]{8})", ifc)
    if not m:
        return None
    ip = m.group(1)
    prefix = bin(int(m.group(2), 16)).count("1")
    mac_m = re.search(r"ether ([0-9a-f:]{17})", ifc)
    # Hardware port type
    ports = _run(["networksetup", "-listallhardwareports"])
    kind = "unknown"
    for block in ports.split("\n\n"):
        if f"Device: {dev}" in block:
            kind = "wifi" if "Wi-Fi" in block or "AirPort" in block else "ethernet"
    ssid = ""
    if kind == "wifi":
        m2 = re.search(r"Current Wi-Fi Network:\s*(.+)", _run(["networksetup", "-getairportnetwork", dev]))
        if m2:
            ssid = m2.group(1).strip()
    return NetworkInfo(connected=True, kind=kind, ssid=ssid, interface=dev, ip=ip, prefix=prefix,
                       gateway=gw.group(1) if gw else "", mac=mac_m.group(1) if mac_m else "",
                       method="macos/networksetup")


# --------------------------------------------------------------------------- #
# public API
# --------------------------------------------------------------------------- #


# Detect the current network. Never raises; connected tells the story.
def detect_network() -> NetworkInfo:
    local_ip = primary_ip()
    system = platform.system().lower()
    info: Optional[NetworkInfo] = None
    try:
        if system.startswith("win"):
            info = _detect_windows(local_ip)
        elif system == "linux":
            info = _detect_linux(local_ip)
        elif system == "darwin":
            info = _detect_macos(local_ip)
    except Exception as exc:  # pragma: no cover - platform tooling surprises
        log.debug("network detection failed: %s", exc)
        info = None

    if info and _is_private_usable(info.ip):
        return info

    if local_ip and _is_private_usable(local_ip):
        fallback = NetworkInfo(connected=True, kind="unknown", ip=local_ip, prefix=24,
                               method="fallback/udp-route")
        fallback.notes.append("interface details unavailable; assuming a /24 network")
        return fallback

    return NetworkInfo(connected=False, method="none", notes=["no default route / no IPv4 address"])

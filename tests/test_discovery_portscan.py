import socket
import threading
from unittest import mock

import pytest

from cybersweep import discovery, portscan
from cybersweep.models import Host


def _closed_port() -> int:
    """Return a port number on loopback that is currently closed."""
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --------------------------------------------------------------------------- #
# discovery
# --------------------------------------------------------------------------- #


def test_tcp_probe_detects_open_port(ssh_server):
    assert discovery.tcp_probe("127.0.0.1", ports=[ssh_server.port], timeout=1) is True


def test_tcp_probe_detects_closed_port_as_alive():
    assert discovery.tcp_probe("127.0.0.1", ports=[_closed_port()], timeout=1) is True


def test_tcp_probe_timeout_is_dead():
    # 192.0.2.0/24 is TEST-NET-1: guaranteed unroutable.
    assert discovery.tcp_probe("192.0.2.123", ports=[80], timeout=0.2) is False


def test_ping_probe_uses_platform_flags(monkeypatch):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return mock.Mock(returncode=0)

    monkeypatch.setattr(discovery.subprocess, "run", fake_run)
    monkeypatch.setattr(discovery, "is_windows", lambda: True)
    assert discovery.ping_probe("10.0.0.1", 1500) is True
    assert calls[-1][:5] == ["ping", "-n", "1", "-w", "1500"]

    monkeypatch.setattr(discovery, "is_windows", lambda: False)
    discovery.ping_probe("10.0.0.1", 1500)
    assert calls[-1][:3] == ["ping", "-c", "1"]


def test_ping_probe_handles_missing_binary(monkeypatch):
    monkeypatch.setattr(discovery.subprocess, "run", mock.Mock(side_effect=OSError("no ping")))
    assert discovery.ping_probe("10.0.0.1") is False


def test_discover_tcp_sweep(ssh_server):
    hosts = discovery.discover_tcp(["127.0.0.1", "192.0.2.77"], timeout=0.3)
    assert [h.ip for h in hosts] == ["127.0.0.1"]
    assert hosts[0].discovery_method == "tcp"


def test_discover_hosts_falls_back_when_nmap_missing(monkeypatch):
    monkeypatch.setattr(discovery, "nmap_available", lambda: False)
    monkeypatch.setattr(discovery, "discover_tcp", lambda ips, *a, **k: [Host(ip=ips[0], discovery_method="tcp")])
    hosts, used = discovery.discover_hosts(["10.0.0.1"], method="arp", resolve_names=False)
    assert used == "tcp" and hosts[0].ip == "10.0.0.1"


def test_discover_hosts_combined_merges_results(monkeypatch):
    monkeypatch.setattr(discovery, "nmap_available", lambda: False)
    monkeypatch.setattr(discovery, "discover_tcp", lambda ips, *a, **k: [Host(ip="10.0.0.2", discovery_method="tcp")])
    monkeypatch.setattr(discovery, "discover_ping", lambda ips, *a, **k: [Host(ip="10.0.0.1", discovery_method="ping")])
    hosts, used = discovery.discover_hosts(["10.0.0.1", "10.0.0.2"], method="auto", resolve_names=False)
    assert used == "tcp+ping"
    assert [h.ip for h in hosts] == ["10.0.0.1", "10.0.0.2"]


def test_discover_arp_parses_nmap_output(monkeypatch):
    fake_host = mock.MagicMock()
    fake_host.state.return_value = "up"
    fake_host.get.side_effect = lambda k, d=None: {
        "addresses": {"ipv4": "10.0.0.5", "mac": "AA:BB:CC:00:11:22"},
        "vendor": {"AA:BB:CC:00:11:22": "Acme Inc"},
    }.get(k, d)
    scanner = mock.MagicMock()
    scanner.all_hosts.return_value = ["10.0.0.5"]
    scanner.__getitem__.return_value = fake_host
    fake_nmap = mock.MagicMock(PortScanner=mock.MagicMock(return_value=scanner))
    monkeypatch.setitem(__import__("sys").modules, "nmap", fake_nmap)

    hosts = discovery.discover_arp(["10.0.0.5", "10.0.0.6"])
    assert len(hosts) == 1
    assert hosts[0].mac == "AA:BB:CC:00:11:22" and hosts[0].vendor == "Acme Inc"
    scanner.scan.assert_called_once()


# --------------------------------------------------------------------------- #
# socket port scanner
# --------------------------------------------------------------------------- #


def test_socket_scanner_open_closed_and_banner(ssh_server):
    scanner = portscan.SocketScanner(timeout=1, threads=4)
    closed = _closed_port()
    host = scanner.scan_host(Host(ip="127.0.0.1"), [ssh_server.port, closed])
    by_port = {p.number: p for p in host.ports}
    assert by_port[ssh_server.port].state == "open"
    assert by_port[ssh_server.port].service == "ssh"
    assert by_port[ssh_server.port].product == "OpenSSH"
    assert by_port[closed].state == "closed"


def test_socket_scanner_filtered_state():
    scanner = portscan.SocketScanner(timeout=0.2, threads=2)
    host = scanner.scan_host(Host(ip="192.0.2.9"), [80])
    assert host.ports[0].state == "filtered"


def test_socket_scanner_drops_closed_ports_for_large_scans(monkeypatch):
    scanner = portscan.SocketScanner(timeout=0.1, threads=50)
    monkeypatch.setattr(scanner, "probe_port",
                        lambda ip, port: portscan.Port(number=port, state="open" if port == 5 else "closed"))
    host = scanner.scan_host(Host(ip="10.0.0.1"), list(range(1, 301)))
    assert [p.number for p in host.ports] == [5]


def test_socket_scanner_cancel():
    cancel = threading.Event()
    cancel.set()
    scanner = portscan.SocketScanner(timeout=0.5, cancel_event=cancel)
    with pytest.raises(portscan.ScanCancelled):
        scanner.scan_host(Host(ip="127.0.0.1"), [1, 2, 3])


def test_make_scanner_choices(monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: False)
    assert isinstance(portscan.make_scanner("auto"), portscan.SocketScanner)
    assert isinstance(portscan.make_scanner("socket"), portscan.SocketScanner)
    with pytest.raises(RuntimeError):
        portscan.make_scanner("nmap")
    with pytest.raises(ValueError):
        portscan.make_scanner("banana")


# --------------------------------------------------------------------------- #
# nmap scanner (mocked)
# --------------------------------------------------------------------------- #


def _fake_nmap_module(host_data: dict, all_hosts=("10.0.0.5",)):
    class FakeHostInfo(dict):
        def state(self):
            return self.get("status", {}).get("state", "up")

        def all_protocols(self):
            return [k for k in ("tcp", "udp") if k in self]

    info = FakeHostInfo(host_data)
    scanner = mock.MagicMock()
    scanner.all_hosts.return_value = list(all_hosts)
    scanner.__getitem__.return_value = info
    module = mock.MagicMock(PortScanner=mock.MagicMock(return_value=scanner))
    module.PortScannerError = RuntimeError
    return module, scanner


def test_nmap_scanner_converts_results(monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: True)
    monkeypatch.setattr(portscan, "python_nmap_available", lambda: True)
    module, scanner = _fake_nmap_module({
        "status": {"state": "up"},
        "addresses": {"ipv4": "10.0.0.5", "mac": "AA:BB:CC:00:11:22"},
        "vendor": {"AA:BB:CC:00:11:22": "Acme"},
        "hostnames": [{"name": "box.lan", "type": "PTR"}],
        "tcp": {
            22: {"state": "open", "name": "ssh", "product": "OpenSSH", "version": "8.9p1",
                 "extrainfo": "Ubuntu Linux", "cpe": "cpe:/a:openbsd:openssh:8.9p1"},
            80: {"state": "closed", "name": "http", "product": "", "version": "", "extrainfo": "", "cpe": ""},
            23: {"state": "open", "name": "telnet", "product": "", "version": "", "extrainfo": "", "cpe": ""},
        },
    })
    monkeypatch.setitem(__import__("sys").modules, "nmap", module)

    ns = portscan.NmapScanner(service_detection=True)
    assert "-sV" in ns.build_arguments()
    host = ns.scan_host(Host(ip="10.0.0.5"), [22, 23, 80])
    assert host.mac == "AA:BB:CC:00:11:22" and host.vendor == "Acme" and host.hostname == "box.lan"
    assert [p.number for p in host.ports] == [22, 23, 80]
    assert host.ports[0].product == "OpenSSH" and host.ports[0].version == "8.9p1"
    assert host.ports[1].service == "telnet"
    assert host.ports[2].state == "closed"
    args = scanner.scan.call_args.kwargs
    assert args["hosts"] == "10.0.0.5" and args["ports"] == "22-23,80"


def test_nmap_scanner_host_missing_from_output(monkeypatch):
    monkeypatch.setattr(portscan, "nmap_available", lambda: True)
    monkeypatch.setattr(portscan, "python_nmap_available", lambda: True)
    module, _ = _fake_nmap_module({}, all_hosts=())
    monkeypatch.setitem(__import__("sys").modules, "nmap", module)
    host = portscan.NmapScanner().scan_host(Host(ip="10.0.0.5"), [22])
    assert host.ports == []

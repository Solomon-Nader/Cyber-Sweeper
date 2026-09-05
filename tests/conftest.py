"""Shared pytest fixtures."""

from __future__ import annotations

import socket
import threading

import pytest

from cybersweep.models import Host, Port, ScanOptions, ScanResult, Vulnerability


@pytest.fixture(autouse=True)
def isolated_home(tmp_path, monkeypatch):
    """Keep the database and CVE cache inside a temporary directory."""
    monkeypatch.setenv("CYBERSWEEP_HOME", str(tmp_path / "home"))
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    yield tmp_path


class BannerServer:
    """A tiny TCP server that sends a fixed banner to every client."""

    def __init__(self, banner: bytes, reply_to_request: bool = False) -> None:
        self.banner = banner
        self.reply_to_request = reply_to_request
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        self.sock.settimeout(0.2)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                if self.reply_to_request:
                    conn.settimeout(1)
                    try:
                        conn.recv(1024)
                    except OSError:
                        pass
                conn.sendall(self.banner)
            except OSError:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self._stop.set()
        self.sock.close()
        self.thread.join(timeout=1)


@pytest.fixture
def ssh_server():
    srv = BannerServer(b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n")
    yield srv
    srv.close()


@pytest.fixture
def http_server():
    srv = BannerServer(b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n\r\n",
                       reply_to_request=True)
    yield srv
    srv.close()


@pytest.fixture
def sample_result() -> ScanResult:
    """A fully populated ScanResult used by storage / report tests."""
    ssh = Port(number=22, state="open", service="ssh", product="OpenSSH", version="8.9p1",
               banner="SSH-2.0-OpenSSH_8.9p1",
               vulnerabilities=[Vulnerability("CVE-2023-38408", "PKCS#11 RCE in ssh-agent",
                                              "CRITICAL", 9.8, "Upgrade OpenSSH", "nvd",
                                              "2023-07-20", "https://nvd.nist.gov/vuln/detail/CVE-2023-38408")])
    telnet = Port(number=23, state="open", service="telnet", product="Telnet",
                  vulnerabilities=[Vulnerability("CS-RULE-001", "Telnet is clear text", "HIGH",
                                                 None, "Use SSH", "rule")])
    closed = Port(number=80, state="closed", service="http")
    host1 = Host(ip="192.168.1.10", hostname="server", mac="AA:BB:CC:DD:EE:FF", vendor="Acme",
                 is_up=True, discovery_method="tcp", ports=[ssh, telnet, closed])
    host2 = Host(ip="192.168.1.2", hostname="", is_up=True, discovery_method="tcp",
                 ports=[Port(number=443, state="open", service="https")])
    down = Host(ip="192.168.1.3", is_up=False)
    result = ScanResult(options=ScanOptions(target="192.168.1.0/28", ports="22,23,80,443"),
                        hosts=[host1, host2, down], engine="socket")
    result.finished_at = result.started_at
    result.notes.append("test note")
    return result

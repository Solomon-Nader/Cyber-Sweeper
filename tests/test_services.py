import pytest

from cybersweeper import services
from cybersweeper.models import Port


@pytest.mark.parametrize("banner, expected", [
    ("SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6\r\n", ("ssh", "OpenSSH", "8.9p1")),
    ("SSH-2.0-dropbear_2020.81", ("ssh", "dropbear", "2020.81")),
    ("HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Debian)\r\n", ("http", "Apache", "2.4.57")),
    ("HTTP/1.1 301 Moved\r\nServer: nginx/1.24.0\r\n", ("http", "nginx", "1.24.0")),
    ("HTTP/1.1 200 OK\r\nServer: nginx\r\n", ("http", "nginx", "")),
    ("HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\n", ("http", "Microsoft-IIS", "10.0")),
    ("HTTP/1.0 200 OK\r\nServer: SimpleHTTP/0.6 Python/3.11.4\r\n", ("http", "SimpleHTTP", "0.6")),
    ("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n", ("http", "HTTP server", "")),
    ("220 (vsFTPd 3.0.5)\r\n", ("ftp", "vsFTPd", "3.0.5")),
    ("220 ProFTPD 1.3.8 Server ready\r\n", ("ftp", "ProFTPD", "1.3.8")),
    ("220 mail.example.com ESMTP Postfix (Ubuntu)\r\n", ("smtp", "Postfix", "")),
    ("220 mx ESMTP Exim 4.96\r\n", ("smtp", "Exim", "4.96")),
    ("+OK Dovecot ready.\r\n", ("pop3", "Dovecot", "")),
    ("* OK [CAPABILITY IMAP4rev1] Dovecot ready.\r\n", ("imap", "Dovecot", "")),
    ("J\x00\x00\x00\x0a8.0.36-0ubuntu0.22.04.1\x00", ("mysql", "MySQL", "8.0.36-0ubuntu0.22.04.1")),
    ("\xff\xfd\x18\xff\xfd login:", ("telnet", "Telnet", "")),
    ("RFB 003.008\n", ("vnc", "VNC", "003.008")),
    ("-NOAUTH Authentication required.\r\n", ("redis", "Redis", "")),
])
def test_identify_from_banner(banner, expected):
    assert services.identify_from_banner(banner) == expected


def test_identify_unknown_banner_returns_none():
    assert services.identify_from_banner("hello world") is None
    assert services.identify_from_banner("") is None


def test_identify_falls_back_to_well_known_table():
    p = services.identify(Port(number=3306, banner=""))
    assert p.service == "mysql"
    assert p.product == ""


def test_identify_unknown_port_without_banner():
    p = services.identify(Port(number=61234, banner=""))
    assert p.service == "unknown"


def test_identify_does_not_override_nmap_data():
    p = Port(number=2222, service="ssh", product="OpenSSH", version="9.0", banner="SSH-2.0-OpenSSH_8.9")
    services.identify(p)
    assert (p.product, p.version) == ("OpenSSH", "9.0")


def test_clean_banner_is_single_line_and_printable():
    cleaned = services.clean_banner("HTTP/1.0 200 OK\r\nServer: x\r\n\r\n\x00\x01binary")
    assert "\n" not in cleaned and "\x00" not in cleaned
    assert cleaned.startswith("HTTP/1.0 200 OK | Server: x")


def test_grab_banner_from_live_ssh_server(ssh_server):
    import socket

    s = socket.create_connection(("127.0.0.1", ssh_server.port), timeout=2)
    banner = services.grab_banner(s, ssh_server.port, timeout=2)
    s.close()
    assert banner.startswith("SSH-2.0-OpenSSH_8.9p1")


def test_grab_banner_sends_http_request(http_server, monkeypatch):
    import socket

    from cybersweeper import config

    monkeypatch.setattr(config, "HTTP_PORTS", set(config.HTTP_PORTS) | {http_server.port})
    s = socket.create_connection(("127.0.0.1", http_server.port), timeout=2)
    banner = services.grab_banner(s, http_server.port, timeout=2)
    s.close()
    assert "nginx/1.24.0" in banner

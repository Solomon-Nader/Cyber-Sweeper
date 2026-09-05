"""Service identification.

Given an open port, CyberSweep tries to work out *what* is listening on it:

1. **Banner grabbing** - read whatever the service sends on connect (SSH, FTP,
   SMTP, POP3, IMAP, MySQL ...) or send a minimal HTTP request and read the
   response headers.
2. **Fingerprint matching** - a table of regular expressions turns the banner
   into ``service`` / ``product`` / ``version`` fields.
3. **Well-known port table** - if the banner is silent or unrecognised, fall
   back to the IANA-style service name for that port number.

When the nmap engine is used, nmap's own ``-sV`` data takes precedence and
this module only fills in gaps.
"""

from __future__ import annotations

import re
import socket
from dataclasses import dataclass
from typing import Optional

from cybersweep import config
from cybersweep.models import Port


@dataclass(frozen=True)
class Fingerprint:
    service: str
    pattern: re.Pattern
    product_group: Optional[int] = None
    version_group: Optional[int] = None
    product: str = ""  # constant product name when the banner has none


def _fp(service: str, pattern: str, product_group: Optional[int] = None,
        version_group: Optional[int] = None, product: str = "") -> Fingerprint:
    return Fingerprint(service, re.compile(pattern, re.IGNORECASE | re.DOTALL),
                       product_group, version_group, product)


# Order matters: more specific patterns first.
FINGERPRINTS: list[Fingerprint] = [
    _fp("ssh", r"^SSH-\d\.\d-(OpenSSH)[_-]([\w.]+)", 1, 2),
    _fp("ssh", r"^SSH-\d\.\d-(dropbear)[_-]?([\w.]*)", 1, 2),
    _fp("ssh", r"^SSH-\d\.\d-([\w.-]+)", 1, None),
    _fp("http", r"Server:\s*(Apache)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(nginx)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(nginx)", 1, None),
    _fp("http", r"Server:\s*(Microsoft-IIS)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(lighttpd)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(gunicorn)/?([\d.]*)", 1, 2),
    _fp("http", r"Server:\s*(Werkzeug)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(SimpleHTTP)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(Jetty)\(([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*(Apache-Coyote)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*([^\r\n/]+)/([\d.]+)", 1, 2),
    _fp("http", r"Server:\s*([^\r\n]+)", 1, None),
    _fp("http", r"^HTTP/\d\.\d \d{3}", None, None, product="HTTP server"),
    _fp("ftp", r"^220[ -].*?(vsFTPd) ([\d.]+)", 1, 2),
    _fp("ftp", r"^220[ -].*?(ProFTPD) ([\d.]+)", 1, 2),
    _fp("ftp", r"^220[ -].*?(FileZilla Server) ([\d.]+)", 1, 2),
    _fp("ftp", r"^220[ -].*?(Pure-FTPd)", 1, None),
    _fp("ftp", r"^220[ -].*?(Microsoft FTP Service)", 1, None),
    _fp("ftp", r"^220[ -].*FTP", None, None, product="FTP server"),
    _fp("smtp", r"^220[ -].*?(Postfix)", 1, None),
    _fp("smtp", r"^220[ -].*?(Exim) ([\d.]+)", 1, 2),
    _fp("smtp", r"^220[ -].*?(Sendmail) ([\d./]+)", 1, 2),
    _fp("smtp", r"^220[ -].*?Microsoft (ESMTP MAIL Service)", None, None, product="Microsoft Exchange SMTP"),
    _fp("smtp", r"^220[ -].*?[ES]SMTP", None, None, product="SMTP server"),
    _fp("pop3", r"^\+OK.*?(Dovecot)", 1, None),
    _fp("pop3", r"^\+OK.*POP3?", None, None, product="POP3 server"),
    _fp("imap", r"^\* OK.*?(Dovecot)", 1, None),
    _fp("imap", r"^\* OK.*IMAP", None, None, product="IMAP server"),
    _fp("mysql", r"^.\x00\x00\x00\x0a(\d+\.\d+\.\d+[\w.-]*)", None, 1, product="MySQL"),
    _fp("mysql", r"(\d+\.\d+\.\d+)-MariaDB", None, 1, product="MariaDB"),
    _fp("mysql", r"is not allowed to connect to this (MySQL|MariaDB) server", 1, None),
    _fp("redis", r"^-ERR|^\+PONG|-NOAUTH", None, None, product="Redis"),
    _fp("telnet", r"^\xff[\xfb-\xfe]", None, None, product="Telnet"),
    _fp("vnc", r"^RFB (\d{3}\.\d{3})", None, 1, product="VNC"),
    _fp("rdp", r"^\x03\x00\x00", None, None, product="Microsoft RDP"),
    _fp("microsoft-ds", r"^\x00\x00\x00.\xffSMB", None, None, product="SMB"),
    _fp("mongodb", r"MongoDB", None, None, product="MongoDB"),
    _fp("postgresql", r"(FATAL|PostgreSQL|SFATAL)", None, None, product="PostgreSQL"),
    _fp("elasticsearch", r"\"cluster_name\"", None, None, product="Elasticsearch"),
    _fp("rtsp", r"^RTSP/1\.0", None, None, product="RTSP server"),
    _fp("sip", r"^SIP/2\.0", None, None, product="SIP server"),
]


def grab_banner(sock: socket.socket, port: int,
                timeout: float = config.DEFAULT_BANNER_TIMEOUT) -> str:
    """Read a service banner from an already-connected socket.

    For HTTP-like ports a ``HEAD`` request is sent first because web servers
    do not talk until asked. Non-printable bytes are kept (escaped) because
    binary protocols such as MySQL and RDP are recognised from them.
    """
    sock.settimeout(timeout)
    try:
        if port in config.HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: localhost\r\nUser-Agent: CyberSweep\r\n\r\n")
        elif port in config.HTTPS_PORTS:
            return ""  # TLS handshake needed; leave to nmap or the table
        data = sock.recv(1024)
        if not data and port not in config.HTTP_PORTS:
            # Some services need a nudge (e.g. HTTP on a non-standard port).
            sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            data = sock.recv(1024)
    except (OSError, socket.timeout):
        return ""
    return data.decode("latin-1", errors="replace")[:1024]


def identify_from_banner(banner: str) -> Optional[tuple[str, str, str]]:
    """Return ``(service, product, version)`` for a banner, or None."""
    if not banner:
        return None
    for fp in FINGERPRINTS:
        m = fp.pattern.search(banner)
        if not m:
            continue
        product = fp.product
        version = ""
        if fp.product_group is not None:
            product = (m.group(fp.product_group) or "").strip()
        if fp.version_group is not None:
            version = (m.group(fp.version_group) or "").strip()
        return fp.service, product, version
    return None


def clean_banner(banner: str) -> str:
    """Return a one-line, printable version of a banner for display/storage."""
    lines = []
    for raw in banner.replace("\r", "\n").split("\n"):
        printable = "".join(ch if 32 <= ord(ch) < 127 else " " for ch in raw).strip()
        if printable:
            lines.append(" ".join(printable.split()))
    return " | ".join(lines[:3])[:200]


def identify(port: Port) -> Port:
    """Populate ``service``/``product``/``version`` on *port* in place."""
    guess = identify_from_banner(port.banner)
    if guess:
        service, product, version = guess
        port.service = port.service or service
        port.product = port.product or product
        port.version = port.version or version
    if not port.service:
        port.service = config.WELL_KNOWN_SERVICES.get(port.number, "unknown")
    if port.number in config.HTTPS_PORTS and port.service in ("https", "https-alt"):
        port.product = port.product or "TLS web server"
    port.banner = clean_banner(port.banner)
    return port

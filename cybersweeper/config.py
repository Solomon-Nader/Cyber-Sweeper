# Central configuration and static reference data for Cyber Sweeper.
#
# Everything here is plain data: default timeouts, well-known port tables and the
# list of ports that make up the top100 / common presets.

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "Cyber Sweeper"
BANNER = r"""
   ______      __                 _____
  / ____/_  __/ /_  ___  _____   / ___/      _____  ___  ____  ___  _____
 / /   / / / / __ \/ _ \/ ___/   \__ \ | /| / / _ \/ _ \/ __ \/ _ \/ ___/
/ /___/ /_/ / /_/ /  __/ /      ___/ / |/ |/ /  __/  __/ /_/ /  __/ /
\____/\__, /_.___/\___/_/      /____/|__/|__/\___/\___/ .___/\___/_/
     /____/            Network Inspector             /_/
"""

LEGAL_NOTICE = (
    "Only scan systems you own or are explicitly authorised to test. "
    "Unauthorised scanning may be illegal in your jurisdiction."
)

# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #


DIR_NAME = ".cybersweeper"
DB_NAME = "cybersweeper.db"
LEGACY_DIR_NAME = ".cybersweep"  # names used before the 2.0.0 rename
LEGACY_DB_NAME = "cybersweep.db"


# Carry a pre-2.0.0 ~/.cybersweep directory over to the new name.
#
# Version 2.0.0 renamed the project, and with it both this directory and the
# database inside it. Moving them once keeps scan history that was saved
# before the rename. Any failure is ignored: a fresh directory is created
# instead, which costs history but never blocks a scan.
def _migrate_legacy(home: Path, path: Path) -> None:
    legacy = home / LEGACY_DIR_NAME
    if path.exists() or not legacy.is_dir():
        return
    try:
        legacy.rename(path)
        old_db = path / LEGACY_DB_NAME
        if old_db.is_file() and not (path / DB_NAME).exists():
            old_db.rename(path / DB_NAME)
    except OSError:  # pragma: no cover - permissions, or a race with another process
        pass


# Return (and create) the directory used for the database and caches.
#
# The location can be overridden with the CYBERSWEEPER_HOME environment
# variable, which is handy for Docker volumes and for tests.
def data_dir() -> Path:
    root = os.environ.get("CYBERSWEEPER_HOME")
    if root:
        path = Path(root)
    else:
        home = Path.home()
        path = home / DIR_NAME
        _migrate_legacy(home, path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def default_db_path() -> Path:
    return data_dir() / DB_NAME


def default_cache_path() -> Path:
    return data_dir() / "cve_cache.json"


# --------------------------------------------------------------------------- #
# Scanning defaults
# --------------------------------------------------------------------------- #

DEFAULT_CONNECT_TIMEOUT = 1.0  # seconds for a TCP connect probe
DEFAULT_BANNER_TIMEOUT = 2.0  # seconds to wait for a service banner
DEFAULT_THREADS = 100  # concurrent socket probes
DEFAULT_PING_TIMEOUT_MS = 1000
MAX_HOSTS_WITHOUT_CONFIRMATION = 4096  # refuse absurd ranges (e.g. /8) by default

# Ports probed during TCP-based host discovery (a host answering on any of these
# - even with a RST - is considered alive).
DISCOVERY_PROBE_PORTS = [80, 443, 22, 445, 139, 135, 3389, 21, 25, 8080]

# The 100 most common TCP ports (based on the nmap-services frequency data).
TOP_100_PORTS = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113, 119, 135,
    139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514, 515, 543, 544, 548,
    554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026, 1027, 1028, 1029, 1110, 1433,
    1720, 1723, 1755, 1900, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3389, 3986,
    4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000,
    6001, 6646, 7070, 8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768,
    49152, 49153, 49154, 49155, 49156, 49157,
]

# A smaller set for very quick scans.
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                1433, 1723, 3306, 3389, 5432, 5900, 8080, 8443]

PORT_PRESETS = {
    "common": COMMON_PORTS,
    "top100": TOP_100_PORTS,
    "top1000": list(range(1, 1025)),  # classic "well-known + registered start" sweep
    "all": list(range(1, 65536)),
}

# --------------------------------------------------------------------------- #
# Well-known services (used when no banner or nmap data is available)
# --------------------------------------------------------------------------- #

WELL_KNOWN_SERVICES: dict[int, str] = {
    7: "echo", 9: "discard", 13: "daytime", 20: "ftp-data", 21: "ftp", 22: "ssh",
    23: "telnet", 25: "smtp", 37: "time", 43: "whois", 53: "domain", 67: "dhcp",
    68: "dhcp", 69: "tftp", 79: "finger", 80: "http", 81: "http-alt", 88: "kerberos",
    106: "pop3pw", 110: "pop3", 111: "rpcbind", 113: "ident", 119: "nntp", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 138: "netbios-dgm", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 162: "snmptrap", 179: "bgp", 194: "irc", 199: "smux", 389: "ldap",
    427: "svrloc", 443: "https", 444: "snpp", 445: "microsoft-ds", 465: "smtps",
    500: "isakmp", 512: "exec", 513: "login", 514: "shell", 515: "printer",
    543: "klogin", 544: "kshell", 548: "afp", 554: "rtsp", 587: "submission",
    631: "ipp", 636: "ldaps", 646: "ldp", 873: "rsync", 989: "ftps-data", 990: "ftps",
    993: "imaps", 995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "ms-sql-s",
    1434: "ms-sql-m", 1521: "oracle", 1720: "h323q931", 1723: "pptp", 1883: "mqtt",
    1900: "upnp", 2049: "nfs", 2121: "ftp-alt", 2181: "zookeeper", 2375: "docker",
    2376: "docker-tls", 3000: "node-dev", 3128: "squid-http", 3306: "mysql",
    3389: "ms-wbt-server", 3690: "svn", 4369: "epmd", 4444: "krb524", 5000: "upnp",
    5060: "sip", 5222: "xmpp-client", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5901: "vnc-1", 5984: "couchdb", 5985: "winrm",
    5986: "winrm-https", 6000: "x11", 6379: "redis", 6443: "kubernetes-api",
    6667: "irc", 7001: "weblogic", 8000: "http-alt", 8008: "http", 8009: "ajp13",
    8080: "http-proxy", 8081: "http-alt", 8088: "radan-http", 8443: "https-alt",
    8888: "http-alt", 9000: "cslistener", 9090: "websm", 9100: "jetdirect",
    9200: "elasticsearch", 9300: "elasticsearch-node", 10000: "webmin",
    11211: "memcached", 27017: "mongodb", 27018: "mongodb-shard", 50070: "hadoop",
}

# Ports where the scanner should proactively send a request to elicit a banner.
HTTP_PORTS = {80, 81, 8000, 8008, 8080, 8081, 8088, 8888, 3000, 5000, 9000, 9090, 10000}
HTTPS_PORTS = {443, 8443, 4443, 9443}

# --------------------------------------------------------------------------- #
# Vulnerability lookup
# --------------------------------------------------------------------------- #

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY_ENV = "NVD_API_KEY"
NVD_TIMEOUT = 20  # seconds
NVD_RESULTS_PER_QUERY = 10
# NVD rate limits: 5 requests / 30 s without a key, 50 / 30 s with a key.
NVD_DELAY_NO_KEY = 6.5
NVD_DELAY_WITH_KEY = 0.7
CVE_CACHE_TTL_DAYS = 7

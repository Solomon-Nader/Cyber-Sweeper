<img src="cybersweeper/assets/cybersweeper.png" alt="Cyber Sweeper icon" width="96" align="right">

# Cyber Sweeper — Network Inspector (مفتش الشبكات)

Cyber Sweeper is a Python network inspection tool. It discovers the devices on a
network, scans their ports, identifies the services behind those ports, looks
up known vulnerabilities (CVEs) and produces filterable reports — through both a
command-line interface and a Tkinter graphical interface.

> **Legal notice.** Only scan networks and hosts that you own or have explicit
> written permission to test. Unauthorised scanning may be illegal.

![Cyber Sweeper GUI](docs/images/gui_hosts.png)

## Features

| Area | What Cyber Sweeper does |
|------|----------------------|
| Network detection | Detects whether the machine is online, **Wi-Fi or Ethernet**, the **SSID**, IP/subnet, gateway and MAC — and uses that network as the default target |
| Host discovery | TCP-connect probes (`socket`), ICMP ping, or `nmap -sn` ARP sweeps with MAC/vendor |
| Port scanning | Multithreaded `socket` TCP-connect engine **or** `nmap -sV` through `python-nmap` — auto-selected |
| Service identification | Banner grabbing + 40 regex fingerprints (SSH, HTTP, FTP, SMTP, MySQL, RDP, VNC …) with a well-known-port fallback |
| Vulnerability lookup | 20 built-in configuration rules (offline) + live CVE search in the **NVD API 2.0** with disk caching |
| Technical report | One click / one command produces a finished **PDF or Word assessment report**: risk rating, executive summary, methodology, host inventory, findings register, prioritised remediation plan |
| Reports & exports | Text, Markdown, HTML, CSV, JSON — filter by host, port, service, state, severity; sort by IP/ports/risk |
| Storage | SQLite database of every scan (hosts → ports → findings), CSV export, scan history |
| Interfaces | Full CLI (`network`, `scan`, `discover`, `report`, `history`, `delete`, `check`, `gui`) and a responsive Tkinter GUI |
| Customisation | Target ranges (`10.0.0.0/24`, `10.0.0.1-50`, hostnames), port presets or lists, engine choice, timeouts, thread count |
| Portability | Windows, Linux, macOS · Python 3.9+ · Dockerfile · GitHub Actions CI |

## Installation

### 1. Python

Python 3.9 or newer. Check with `python --version` (Windows) or `python3 --version` (Linux/macOS).

### 2. nmap (recommended, optional)

Cyber Sweeper works without nmap using its own socket engine, but nmap gives more
accurate service/version detection and ARP-based discovery.

| Platform | Command |
|----------|---------|
| Windows | Download the installer from <https://nmap.org/download.html> (tick **Npcap**), then re-open your terminal |
| Debian / Ubuntu / Kali | `sudo apt install nmap` (Kali has it pre-installed) |
| Fedora / RHEL | `sudo dnf install nmap` |
| macOS | `brew install nmap` |

### 3. Cyber Sweeper

**One-command setup** (creates a virtual environment, installs everything, checks
the machine and runs the tests):

```powershell
git clone https://github.com/Solomon-Nader/Cyber-Sweeper.git
cd Cyber-Sweeper
.\scripts\setup.ps1          # Windows PowerShell
bash scripts/setup.sh        # Linux / macOS
```

Or step by step:

```bash
git clone https://github.com/Solomon-Nader/Cyber-Sweeper.git
cd Cyber-Sweeper

# Windows (PowerShell)
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -e .

# Linux / macOS
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Linux users who want the GUI may also need Tk: `sudo apt install python3-tk`.

Verify the environment:

```bash
cybersweeper check
```

## Quick start

```bash
# Which network am I on?  (Wi-Fi/Ethernet, SSID, subnet, gateway)
cybersweeper network

# Scan the network I'm connected to - no address needed
cybersweeper scan                           # auto-detects the network and scans it (top100 ports)
cybersweeper scan -p common                 # same, quicker
cybersweeper discover                       # just list the devices on it

# Or name a target yourself
cybersweeper discover 192.168.1.0/24 -m tcp # force the socket technique

# Scan one host with the 23 most common ports
cybersweeper scan 192.168.1.10 -p common

# Scan a range, look up CVEs online, export everything
cybersweeper scan 192.168.1.0/24 -p 22,80,443,3389,445 --cve \
    --html report.html --csv results.csv --json results.json

# Force an engine
cybersweeper scan 10.0.0.5 -m nmap -p top100
cybersweeper scan 10.0.0.5 -m socket -p 1-1024 --threads 200 -t 0.5

# Technical report documents (PDF / Word) for the latest scan
cybersweeper report -f pdf  -o assessment.pdf  --org "My Company"
cybersweeper report -f docx -o assessment.docx
cybersweeper scan -p common --pdf assessment.pdf   # scan + report in one go

# Work with stored scans
cybersweeper history
cybersweeper report 3                              # text, open ports only
cybersweeper report 3 -f html -o scan3.html --min-severity HIGH
cybersweeper report 3 --service ssh --sort severity
cybersweeper report --state closed --include-down   # latest scan, everything
cybersweeper delete 3

# Graphical interface
cybersweeper gui
```

`python -m cybersweeper ...` works as well if the `cybersweeper` command is not on your PATH.

### Target syntax

| Form | Example |
|------|---------|
| Single IP / hostname | `192.168.1.10`, `router.local` |
| CIDR | `192.168.1.0/24` |
| Range | `192.168.1.10-50`, `192.168.1.250-192.168.2.5` |
| List | `192.168.1.1,192.168.1.20-25,fileserver` |

### Port syntax

`common` (23 ports) · `top100` (default) · `top1000` (1–1024) · `all` (1–65535) · `22,80,443` · `1-1024` · mixes such as `common,8000-8100`.

### CVE lookups

`--cve` queries the NVD for every service whose product and version were
identified. Without an API key the NVD allows 5 requests / 30 s, so lookups are
throttled; results are cached for 7 days in `~/.cybersweeper/cve_cache.json`.
Request a free key at <https://nvd.nist.gov/developers/request-an-api-key> and
set it as an environment variable:

```bash
export NVD_API_KEY=xxxxxxxx      # Linux/macOS
$env:NVD_API_KEY = "xxxxxxxx"    # Windows PowerShell
```

The 20 built-in rules (clear-text protocols, exposed RDP/SMB/databases, etc.)
always run, online or offline.

## Docker

```bash
docker build -t cybersweeper .
docker run --rm --network host -v cybersweeper-data:/data cybersweeper scan 192.168.1.0/24 -p common
docker compose run --rm cybersweeper report
```

`--network host` lets the container see the real LAN (Linux). On Docker Desktop
(Windows/macOS) the container can only reach the Docker VM's network, so run
Cyber Sweeper natively there for LAN scans.

## Project layout

```
cybersweeper/
├── cli.py         argparse command line interface
├── gui.py         Tkinter graphical interface
├── engine.py      pipeline: targets → discovery → port scan → services → vulns
├── netinfo.py     current-network detection (Wi-Fi/Ethernet, SSID, subnet, gateway)
├── discovery.py   TCP / ICMP / ARP(nmap) host discovery
├── portscan.py    SocketScanner and NmapScanner
├── services.py    banner grabbing and fingerprint matching
├── vulns.py       built-in rules + NVD client with cache
├── storage.py     SQLite persistence, CSV/JSON export
├── report.py      filtering, sorting, text/Markdown/HTML rendering
├── techreport.py  PDF / Word technical report documents
├── models.py      Host / Port / Vulnerability / ScanResult dataclasses
├── utils.py       target & port parsing, platform helpers
└── config.py      defaults, port presets, well-known services
tests/             149 pytest tests (network calls are mocked or use loopback)
docs/              user guide, architecture notes, screenshots
```

## Development

```bash
pip install -e ".[dev]"
pytest -q --cov=cybersweeper
ruff check .
```

See [CHANGELOG.md](CHANGELOG.md) for version history, [docs/RELEASING.md](docs/RELEASING.md) for how versions are numbered and published,
[docs/USER_GUIDE.md](docs/USER_GUIDE.md) for a full walkthrough and
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for design notes.

## License

MIT — see [LICENSE](LICENSE).

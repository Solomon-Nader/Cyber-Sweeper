# CyberSweep User Guide

This guide walks through installing CyberSweep, running your first scans from
the command line and the graphical interface, reading the results and exporting
reports.

---

## 1. Before you start

CyberSweep sends packets to the machines it inspects. Use it only on networks
you own or where you have written permission from the owner. A safe way to
practise is on your own home network, a virtual lab (VirtualBox/VMware with a
few VMs), or against `127.0.0.1`.

Requirements:

- Python 3.9 or newer.
- *Optional but recommended:* the `nmap` program (see the README for install
  commands per platform). Without it the built-in socket engine is used.
- *Optional:* Tk for the GUI — bundled with Python on Windows and macOS; on
  Debian/Ubuntu run `sudo apt install python3-tk`.
- *Optional:* an internet connection and an NVD API key for CVE lookups.

Install in a virtual environment:

```bash
git clone https://github.com/Solomon-Nader/Cyber-Sweeper.git
cd Cyber-Sweeper
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1     Linux/macOS: source .venv/bin/activate
pip install -e .
cybersweep check
```

`cybersweep check` prints your Python version, whether nmap and python-nmap
were found, your local IP and the network CyberSweep will scan by default.

---

## 2. Command line

Every command accepts `-h` for help. Global options go **before** the command
name: `cybersweep --db mydb.sqlite --verbose scan ...`.

| Command | Purpose |
|---------|---------|
| `check` | Environment diagnostics |
| `discover [target]` | List live hosts (default target: your local /24) |
| `scan <target>` | Discovery + port scan + service identification (+ CVE lookup) |
| `report [id]` | Re-render a stored scan with filters (default: latest) |
| `history` | List stored scans |
| `delete <id>` | Remove a stored scan |
| `gui` | Launch the graphical interface |

### 2.1 Discovering hosts

```bash
cybersweep discover                     # local network, best available method
cybersweep discover 192.168.1.0/24 -m ping
cybersweep discover 10.0.0.1-50 -m tcp --no-dns
```

Methods: `auto` (nmap ARP when available, else TCP+ping), `tcp` (connect probes
to common ports — works without privileges anywhere), `ping` (ICMP via the
system `ping` command), `arp` (`nmap -sn`, returns MAC address and vendor on the
local segment).

### 2.2 Scanning

```bash
cybersweep scan 192.168.1.10                    # top 100 ports, auto engine
cybersweep scan 192.168.1.10 -p common          # 23 most common ports (fast)
cybersweep scan 192.168.1.0/24 -p 22,80,443     # whole network, 3 ports
cybersweep scan 192.168.1.10 -p 1-1024 -m socket --threads 200 -t 0.5
cybersweep scan 192.168.1.10 -m nmap            # force nmap -sV
cybersweep scan 192.168.1.10 --cve              # add NVD CVE lookup
```

Useful options:

- `-p/--ports` — `common`, `top100`, `top1000`, `all`, explicit lists/ranges.
- `-m/--method` — `auto`, `socket`, `nmap`.
- `--discovery tcp|ping|arp|auto` and `--no-discovery` (scan every address even
  if it looks down — like `nmap -Pn`). Single-host targets skip discovery.
- `--no-service` — skip banner grabbing / `-sV` for a faster port-only scan.
- `-t/--timeout` and `--threads` — tune speed vs. reliability. Lower timeouts
  are fine on a LAN; raise them over Wi-Fi or VPN links.
- `--csv FILE`, `--json FILE`, `--html FILE` — export immediately.
- `--no-save` — do not write to the database.
- `--all-states` — show closed/filtered ports in the console table.

Press **Ctrl+C** at any time to cancel.

Reading the console table:

```
+----------+-------+---------+-----------------+---------------------------+--------+
| PORT     | STATE | SERVICE | PRODUCT/VERSION | BANNER                    | RISK   |
+----------+-------+---------+-----------------+---------------------------+--------+
| 22/tcp   | open  | ssh     | OpenSSH 8.9p1   | SSH-2.0-OpenSSH_8.9p1 ... |        |
| 23/tcp   | open  | telnet  | Telnet          | login:                    | HIGH   |
+----------+-------+---------+-----------------+---------------------------+--------+
  [HIGH] 23/tcp CS-RULE-001: Telnet transmits credentials and session data in clear text.
      -> Disable Telnet and use SSH for remote administration.
```

- **STATE** — `open` (service answered), `closed` (host refused), `filtered`
  (no answer, probably a firewall).
- **PRODUCT/VERSION** — from the banner or nmap; blank when unknown.
- **RISK** — highest severity among the findings on that port.
- Findings starting with `CS-RULE-` come from the built-in rules; `CVE-…`
  entries come from the NVD and link to the official advisory.

### 2.3 Reports and filters

Every scan is stored in `~/.cybersweep/cybersweep.db` (or `$CYBERSWEEP_HOME`).

```bash
cybersweep history                                   # list scans with counts
cybersweep report                                    # latest scan, text
cybersweep report 4 -f html -o scan4.html            # HTML report
cybersweep report 4 -f markdown                      # Markdown to stdout
cybersweep report 4 -f csv -o scan4.csv              # flat CSV
cybersweep report 4 --host 192.168.1.1 --port 80 --port 443
cybersweep report 4 --service ssh --service http
cybersweep report 4 --min-severity HIGH --sort severity
cybersweep report 4 --vulnerable                     # only ports with findings
cybersweep report 4 --state closed --state open --include-down
```

Filters combine with AND. `--sort` accepts `ip`, `open_ports`, `severity`.

### 2.4 CVE lookups

`--cve` searches the NVD by product + version for each identified service.

- Without a key the NVD permits 5 requests per 30 seconds, so CyberSweep waits
  ~6.5 s between queries. Set `NVD_API_KEY` for 50 requests / 30 s.
- Results are cached in `cve_cache.json` for 7 days, so repeat scans are fast
  and work offline for known services.
- Generic products (e.g. "HTTP server") are not searched because the results
  would be meaningless. Only services with a specific product name are queried.
- Any network problem is reported in the scan notes; the scan itself still
  completes.

---

## 3. Graphical interface

```bash
cybersweep gui
```

![Hosts & ports tab](images/gui_hosts.png)

1. **Scan options** — enter a target (your local network is pre-filled), pick a
   port preset or type your own, choose the engine and timeout, and tick
   *Host discovery*, *Service detection* and *CVE lookup* as needed.
2. **Start scan** — the progress bar and status line show the current phase.
   Scans run in the background; **Stop** cancels.
3. **Hosts & ports** tab — one row per port. Click a column header to sort.
   Rows are coloured by risk.
4. **Findings** tab — every rule hit and CVE with severity, CVSS score, summary
   and recommendation. Double-click a row for the full text and NVD link.
5. **Log** tab — what the engine did, including notes such as the discovery
   method used or nmap fallbacks.
6. **Filter bar** — free-text filter (IP, hostname, service, product, banner),
   minimum severity, and *Open ports only*.
7. **Export** — CSV, HTML or JSON of the current scan with the current filter.
8. **History…** — load or delete earlier scans from the database.

![Findings tab](images/gui_findings.png)

Scanning more than one address asks you to confirm that you are authorised.

---

## 4. Files and data

| Item | Location |
|------|----------|
| Database | `~/.cybersweep/cybersweep.db` |
| CVE cache | `~/.cybersweep/cve_cache.json` |
| Override directory | set `CYBERSWEEP_HOME=/some/path` |
| Per-command DB | `cybersweep --db path/to/file.db …` |

Delete the database file to start fresh; it is recreated automatically.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---------|-------------|
| `nmap binary : NOT found` in `check` | Install nmap and restart the terminal so PATH is refreshed. Windows: use the official installer with Npcap. |
| `--method nmap` error | Same as above, or `pip install python-nmap`. |
| Everything shows `filtered` | A firewall drops the probes, or the timeout is too short over Wi-Fi/VPN. Try `-t 2` or `--no-discovery`. |
| Discovery finds nothing but hosts exist | Windows firewalls often block ping and unsolicited TCP. Try `--discovery arp` (needs nmap) or `--no-discovery`. |
| No MAC/vendor column | MAC addresses are only visible on the local segment and only with the nmap/ARP method (may need administrator/root). |
| CVE lookup reports HTTP 403 | NVD rate limit. Wait 30 s or set `NVD_API_KEY`. |
| GUI fails with "No module named tkinter" | `sudo apt install python3-tk` (Debian/Ubuntu). |
| Very slow full-port scans | Use the socket engine with `--threads 300 -t 0.3` on a LAN, or restrict the range. |

---

## 6. Ethics and safety

CyberSweep only performs *passive-to-light* actions: TCP connections, reading
banners, ICMP echo requests and (through nmap) service probes. It does not
exploit vulnerabilities, brute-force credentials or modify anything on the
targets. Even so, port scanning without permission can violate laws and
acceptable-use policies. Always obtain authorisation first.

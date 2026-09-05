# CyberSweep Architecture

## Layered design

```
┌───────────────────────────────────────────────────────────────────┐
│  Presentation        cli.py (argparse)          gui.py (Tkinter)  │
├───────────────────────────────────────────────────────────────────┤
│  Application         engine.ScanEngine  ─ pipeline + progress     │
├───────────────────────────────────────────────────────────────────┤
│  Domain services     discovery.py   portscan.py   services.py     │
│                      vulns.py       report.py                     │
├───────────────────────────────────────────────────────────────────┤
│  Data                models.py (dataclasses)   storage.py (SQLite)│
├───────────────────────────────────────────────────────────────────┤
│  Infrastructure      socket · subprocess(ping) · python-nmap ·    │
│                      requests (NVD API) · sqlite3 · csv/json      │
└───────────────────────────────────────────────────────────────────┘
```

The interfaces never talk to sockets or nmap directly; they build a
`ScanOptions`, hand it to `ScanEngine`, receive progress callbacks and finally a
`ScanResult`. Everything below the engine is plain Python that can be tested
without a network (see `tests/`).

## Scan pipeline

```
target spec ──▶ utils.parse_targets ──▶ [ip, ip, ...]
port spec   ──▶ utils.parse_ports   ──▶ [port, ...]
                       │
                       ▼
          discovery.discover_hosts  (tcp | ping | arp/nmap | auto)
                       │  live Host objects
                       ▼
          portscan.make_scanner  ──▶ SocketScanner | NmapScanner
                       │  Port objects (state, banner / nmap -sV data)
                       ▼
          services.identify  (fingerprints → service/product/version)
                       │
                       ▼
          vulns.assess_host  (built-in rules + NVDClient with cache)
                       │
                       ▼
          ScanResult ──▶ storage.Database.save_scan ──▶ SQLite
                     ──▶ report.render (text/markdown/html)
                     ──▶ storage.export_csv / export_json
```

## Key decisions

**Two scanning engines.** The `socket` engine guarantees the tool works on any
machine (Windows without Npcap, restricted lab VMs, Docker without
capabilities). nmap is used automatically when present because its `-sV`
probes and service database are far richer than what a hand-written banner
grabber can do. Both produce identical `Host`/`Port` objects.

**Discovery is best-effort and layered.** TCP-connect probes to ten common
ports detect Windows hosts that block ICMP; ping detects hosts with all probed
ports filtered; `nmap -sn` adds ARP on the local segment. "auto" picks nmap if
available, otherwise TCP + ping merged.

**Threading, not asyncio.** `concurrent.futures.ThreadPoolExecutor` keeps the
code approachable and works identically with blocking `socket.connect_ex`,
`subprocess.run` and the synchronous python-nmap API. A `threading.Event`
propagates cancellation from the GUI/CLI into worker threads.

**Vulnerability data from two sources.** Version-specific CVEs come from the
NVD REST API (keyword search on `product version`), cached on disk with a TTL
so the tool degrades gracefully offline and respects NVD rate limits. Version-
independent weaknesses (Telnet, exposed RDP/SMB/DB ports…) come from a small
rule table so the tool always gives actionable advice, even with no internet.

**SQLite over CSV as the primary store.** Relational tables make history,
filtering and per-scan reports trivial, and SQLite ships with Python. CSV/JSON
remain available as flat exports for spreadsheets and other tools.

**Filters live in one place.** `report.ReportFilter` is used by the CLI
(`report --host/--port/--service/--min-severity`), by the GUI filter bar and by
all renderers, so behaviour is consistent.

**Safety guards.** Target expansion refuses more than 4096 hosts unless
`--max-hosts` is raised; the GUI asks for confirmation before multi-host scans;
the banner and reports repeat the legal notice; the tool never sends exploit
payloads.

## Data model

```
ScanResult
 ├─ options: ScanOptions (target, ports, method, discover, cve_lookup, timeout, threads…)
 ├─ engine, started_at, finished_at, notes[], scan_id
 └─ hosts: [Host]
      ├─ ip, hostname, mac, vendor, os_guess, is_up, discovery_method
      └─ ports: [Port]
           ├─ number, protocol, state, service, product, version, banner
           └─ vulnerabilities: [Vulnerability]
                └─ cve_id, summary, severity, cvss_score, recommendation, source, published, url
```

The SQLite schema mirrors this tree (`scans` → `hosts` → `ports` →
`vulnerabilities`) with cascading deletes.

## Testing strategy

- **Pure logic** (parsing, fingerprints, filters, renderers, NVD JSON parsing)
  is tested directly.
- **Network code** is tested against loopback servers started by the test
  suite (`BannerServer` in `conftest.py`) and against TEST-NET-1 addresses
  (`192.0.2.x`) that are guaranteed unroutable, so results are deterministic.
- **nmap and ping** are mocked (`unittest.mock`), so the suite runs on CI
  runners without nmap and without privileges.
- **Storage** uses temporary SQLite files; `CYBERSWEEP_HOME` is redirected to a
  temp directory for every test.
- **CLI** is exercised end-to-end through `cli.main([...])` with captured
  stdout.

Run with `pytest -q --cov=cybersweep`.

## Extending

- New fingerprint: add a `_fp(...)` entry to `services.FINGERPRINTS`.
- New offline rule: add a `_rule(...)` to `vulns.BUILTIN_RULES`.
- New report format: add a renderer to `report.RENDERERS`.
- New scan engine: implement `scan_host(host, ports, progress)` and return
  `Port` objects; register it in `portscan.make_scanner`.

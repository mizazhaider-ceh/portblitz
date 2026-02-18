<div align="center">

```
    ⚡ P O R T B L I T Z ⚡

    Ultra-fast Async Port Scanner
    v5.0  ·  Command Center Edition
```

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![License MIT](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](LICENSE)
[![AsyncIO](https://img.shields.io/badge/Core-AsyncIO-7c3aed?style=for-the-badge&logo=python&logoColor=white)](https://docs.python.org/3/library/asyncio.html)
[![Zero Dependencies](https://img.shields.io/badge/Deps-Zero-f59e0b?style=for-the-badge)](requirements.txt)

**Next-generation async port scanner with built-in intelligence engine, CDN/WAF detection, and interactive command center.**

[Features](#-features) · [Install](#-installation) · [Usage](#-usage) · [Architecture](#-architecture) · [Security](#-security)

</div>

---

## Overview

**PortBlitz** is a high-performance TCP port scanner built on Python's `asyncio` framework. It scans thousands of ports per second while providing accurate results through automatic **CDN/WAF false-positive detection** — a feature absent from most open-source scanners.

**v5.0 "Command Center"** introduces an interactive TUI, session management, script engine (PBSE), CVE correlation, and external tool bridging (Nmap/Nuclei).

### What Makes PortBlitz Different

| Problem | PortBlitz Solution |
|:---|:---|
| Scanners report **every port open** behind Cloudflare/CDN | **Canary-port probing** detects catch-all proxies, switches to banner-verified mode |
| Banner injection → XSS in HTML reports | All output **HTML-escaped** before rendering |
| External tool calls via shell strings → command injection | Uses `create_subprocess_exec` with **strict input validation** |
| Slow sequential scanning | **Async semaphore pool** with configurable concurrency (default 500) |

---

## Features

| Module | Description | Flag |
|:---|:---|:---|
| **Command Center** | Interactive TUI with session management, rich help, and visual config display | `-i` |
| **Async Scanner** | Non-blocking TCP connect scanning — 1000+ ports/sec | *(core)* |
| **CDN/WAF Detection** | Canary-port probing eliminates false positives from reverse proxies | *(automatic)* |
| **Banner Grabbing** | TCP banner + SSL probe + HTTP title extraction | *(automatic)* |
| **Service Detection** | Regex-based identification from banners (20+ signatures) | *(automatic)* |
| **CVE Correlation** | Match banners against known vulnerable versions | `--vuln` |
| **Script Engine (PBSE)** | Extensible Python scripts for auth checks, header auditing | `--scripts` |
| **Tool Bridge** | Auto-trigger Nmap/Nuclei on open ports (safe subprocess) | `--bridge` |
| **WAF Evasion** | Random User-Agent rotation + jitter delays | `--waf` |
| **Rate Limiting** | Token-bucket rate limiter for stealth scanning | `--rate N` |
| **HTML Reports** | Dark-themed responsive reports with intelligence data | *(automatic)* |
| **JSON/CSV Export** | Machine-readable output for pipeline integration | `--json` `--csv` |
| **Live Host Discovery** | TCP ping + ICMP fallback before scanning | *(automatic)* |

---

## Installation

```bash
git clone https://github.com/mizazhaider-ceh/portblitz.git
cd portblitz
python portblitz.py --help
```

> **Zero external dependencies** — runs on Python 3.8+ stdlib only.

---

## Usage

### Interactive Command Center (Recommended)

```bash
python portblitz.py -i
```

```
  ⚡ PortBlitz v5.0 — Interactive Command Center ⚡

portblitz ❯ set target scanme.nmap.org
  [+] Target → scanme.nmap.org  (1 host)

portblitz ❯ set ports 1-1000
  [+] Ports → 1-1000

portblitz ❯ set vuln on
  [+] vuln → ON

portblitz ❯ show

  ─── SESSION CONFIGURATION ───

  Target     : scanme.nmap.org  (1 host)
  Ports      : 1-1000
  Concurrency: 500
  Rate Limit : Unlimited

  ─── FEATURES ───

  Scripts (PBSE)    OFF
  CVE / Vuln Check  ON
  Tool Bridge       OFF
  WAF Evasion       OFF

portblitz ❯ run

  🚀 Scanning 1 host(s) · 1000 ports

  [+] Port 22    OPEN  (ssh) | SSH-2.0-OpenSSH_6.6.1p1
  [+] Port 80    OPEN  (http) | Title: Go ahead and ScanMe!
  [+] Port 443   OPEN  (https) | SSL: Yes
```

### CLI Quick Scan

```bash
# Standard scan
python portblitz.py 192.168.1.1 -p 1-1000

# Full intelligence scan
python portblitz.py target.com -p 1-1000 --scripts --vuln --waf

# Mass network scan with rate limiting
python portblitz.py 192.168.1.0/24 --rate 100 --json

# Scan from target list
python portblitz.py -iL targets.txt -p top --csv
```

### CDN/WAF Detection in Action

```
[*] Scanning thepentrix.tech (1/1)...

  ⚠  CDN/WAF Detected — 7/8 canary ports accepted TCP.
     Target is likely behind a reverse proxy (Cloudflare, Akamai, etc.).
     Switching to verified-open mode (banner confirmation required).

  [+] Port 80    OPEN  (http) | Title: The PenTrix
  [+] Port 443   OPEN  (https) | SSL: Yes

[+] Completed thepentrix.tech: 2 open ports
```

*Without this detection, the scanner would falsely report 60,000+ "open" ports.*

---

## Command Line Reference

```
positional arguments:
  target                IP, Domain, or CIDR (192.168.1.0/24)

options:
  -h, --help            Show help message
  -i, --interactive     Enter Interactive Command Center
  -iL, --input-list     Read targets from file
  -p, --ports           top | all | 1-1000 | 22,80,443
  -c, --concurrency     Concurrent connections (default: 500)
  -t, --timeout         Socket timeout in seconds (default: 1.0)
  --rate                Rate limit packets/sec (0 = unlimited)
  --noping              Skip live host discovery
  -o, --output          Output directory (default: reports/)

intelligence:
  --scripts             Enable PBSE Script Engine
  --vuln                Enable CVE lookup & vulnerability checks
  --bridge              Enable Tool Bridge (Nmap/Nuclei)
  --waf                 Enable WAF evasion (random UA/delays)

export:
  --json                Export results to JSON
  --csv                 Export results to CSV
```

---

## Architecture

```
portblitz.py           CLI entry point & arg parsing
│
├── core/
│   ├── scanner.py     Async TCP scanner + CDN/WAF false-positive detection
│   ├── orchestrator.py Scan pipeline: live check → rate limit → scan → intel → report
│   ├── console.py     Interactive TUI (cmd.Cmd) with rich help system
│   ├── banner.py      TCP banner grabbing + SSL probing + HTTP title
│   ├── service.py     Regex-based service identification (20+ signatures)
│   ├── engine.py      PBSE script loader & executor
│   ├── live.py        TCP ping + ICMP fallback host discovery
│   ├── rate.py        Token-bucket async rate limiter
│   └── waf.py         Random UA rotation & evasion delays
│
├── modules/
│   └── bridge.py      External tool integration (Nmap/Nuclei) — safe subprocess
│
├── scripts/
│   ├── ftp_weak.py    Anonymous FTP login detection
│   └── http_vuln.py   Directory listing + missing security headers
│
├── utils/
│   ├── display.py     Terminal colors, version, banner
│   ├── net.py         Target parsing (IP/Domain/CIDR/file)
│   ├── report.py      HTML report generation (XSS-safe)
│   ├── export.py      JSON & CSV export
│   ├── cve.py         Static CVE database + regex matching
│   └── charts.py      ASCII bar chart rendering
│
└── tests/
    └── test_portblitz.py  Comprehensive test suite (pytest)
```

### Scan Pipeline

```
Target Input → DNS Resolution → Live Host Check → Rate Limiter
                                      ↓
                              CDN/WAF Detection (canary ports)
                                      ↓
                         ┌── CDN? → Verified-Open Mode (banner required)
                         └── Clean → Standard TCP Connect
                                      ↓
                              Banner Grab + Service ID
                                      ↓
                         ┌── CVE Lookup
                    Intel ├── Script Engine (PBSE)
                         └── Tool Bridge (Nmap/Nuclei)
                                      ↓
                              HTML Report + JSON/CSV
```

---

## Writing PBSE Scripts

Create a Python file in `scripts/` with this structure:

```python
import asyncio
from typing import Dict

TARGET_PORTS = [80, 443]          # Ports that trigger this script
TARGET_SERVICES = ["http", "https"]  # Services that trigger this script

async def run(target: str, port: int, service_info: Dict) -> str:
    """Return a finding string or None."""
    # Your check logic here
    return "VULN: Something found" or None
```

The script engine auto-loads all scripts from `scripts/` and executes matching ones against each open port.

---

## Security

PortBlitz v5.0 includes multiple security hardening measures:

- **XSS Prevention**: All user-controlled data (banners, targets, script output) is HTML-escaped in reports using `html.escape()`
- **Command Injection Prevention**: External tools use `create_subprocess_exec` (not shell) with strict regex validation on inputs
- **No Pickle/Eval**: No deserialization of untrusted data
- **Bare Except Elimination**: All exception handlers specify concrete types

See [SECURITY.md](SECURITY.md) for the full security policy and responsible disclosure process.

---

## Testing

```bash
# Run the test suite
python -m pytest tests/ -v

# Run with coverage
python -m pytest tests/ -v --tb=short
```

---

## Roadmap

- [x] **v1.0** — Core async scanner + HTML reporting
- [x] **v2.0** — Service detection, banner grabbing, SSL probing
- [x] **v3.0** — Mass scanning, CIDR support, rate limiting
- [x] **v4.0** — Script engine (PBSE), CVE lookup, tool bridge
- [x] **v5.0** — Interactive TUI, CDN/WAF detection, security hardening
- [ ] **v6.0** — Scan profiles, result search, diff mode, cloud export

---

## Disclaimer

**PortBlitz** is intended for authorized security testing and network administration only.

- **Do not** scan targets without explicit permission
- The developer assumes **no liability** for unauthorized or illegal use
- Always comply with local laws and organizational policies

---

<div align="center">

**Built by [MIHx0](https://github.com/mizazhaider-ceh) (Mizaz Haider) · Powered by [The PenTrix](https://thepentrix.tech)**

</div>

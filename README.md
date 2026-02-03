# ⚡ PortBlitz v5.0

> **Ultra-fast, Asynchronous Port Scanner, Intelligence Engine & Command Center**  
> *Built for speed, scale, and persistent operations.*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![AsyncIO](https://img.shields.io/badge/Core-AsyncIO-purple)

---

## 📖 Overview

**PortBlitz** is a next-generation network scanner capable of scanning thousands of ports per second. Built on Python's `asyncio` framework, it combines the speed of compiled tools with the intelligence of modern vulnerability scanners.

**v5.0 "Command Center" Release** introduces the **Interactive Console**, **Session Management**, and **Visual Analytics**, transforming PortBlitz into a complete exploitation framework for professionals.

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **🎮 Command Center** | **New Interactive TUI** (`-i`) with persistent session management. |
| **⚡ Blazing Fast** | Non-blocking async engine scans 1000+ ports/sec. |
| **🧠 Intelligence** | **CVE Lookup** & **Script Engine** for auto-vulnerability checks. |
| **🌉 Tool Bridge** | Auto-trigger **Nmap**, **Nuclei**, etc. on open ports. |
| **📊 Visual Analytics** | ASCII Bar Charts & Comprehensive HTML Reports. |
| **🛡️ Stealth/WAF** | **Rate Limiting** (`--rate`) & **WAF Evasion** (`--waf`). |

---

## 📥 Installation

```bash
git clone https://github.com/mizazhaider-ceh/portblitz.git
cd portblitz
# No external dependencies!
python portblitz.py --help
```

---

## 💻 Usage

### 1. The Command Center (v5.0 Recommended)
Enter the interactive shell for professional, persistent scanning.
```bash
python portblitz.py --interactive
```
*Inside the shell:*
```text
portblitz > set target 10.10.10.5
portblitz > set ports top
portblitz > set vuln check on
portblitz > run
```

### 2. Intelligence Scan (CLI Mode)
The ultimate recon scan: Scripts + CVE Mapping + WAF Evasion.
```bash
python portblitz.py target.com -p 1-1000 --scripts --vuln --waf
```

### 3. Mass Network Scan
Scan an entire subnet with rate limiting to stay safe.
```bash
python portblitz.py 192.168.1.0/24 --rate 100 --json
```

---

## ⚙️ Command Line Options

```text
Target:
  target                IP (1.1.1.1), Domain, or CIDR (192.168.1.0/24)
  -iL, --input-list     Read list of targets from file

Intelligence (v4.0):
  --scripts             Enable Script Engine (Auth checks, HTTP headers)
  --vuln                Enable CVE Lookup (Correlate banners with CVEs)
  --bridge              Enable Tool Bridge (Trigger Nmap/Nuclei)
  --waf                 Enable WAF Evasion (Random UA / Delays)

Scan Configuration:
  -p, --ports           Ports: 'top', 'all', range '1-1000', or list '80,443'
  -c, --concurrency     Threads (default: 500)
  --rate                Rate limit (packets/s)
  --noping              Skip live host check

Output:
  -o, --output          Output directory
  --json / --csv        Export formats
```

---

## 🔮 Future Roadmap (Proposed)

We are constantly evolving! Here is what's coming in **v6.0** and beyond:

1.  **Scan Profiles**: Pre-set configs like `stealth` or `loud`.
2.  **Result Search**: Filter results instantly in the console (`search apache`).
3.  **Diff Mode**: Compare scans to detect configuration drift.
4.  **Cloud Export**: Push results to S3/Azure.
5.  **Unified Recon**: Integration with SubHunter for subdomain scanning.
6.  **Notifications**: Slack/Discord alerts on critical findings.
7.  **Auto-Complete**: Tab completion for console commands.
8.  **Screenshots**: Headless browser capture of web ports.
9.  **Exploitation**: Verified exploit checks (Intrusive).
10. **VulnDB Sync**: Live updates for the CVE database.



---

## 🗺️ Roadmap

- [x] **v1.0**: Core Async Loop & HTML Reporting
- [x] **v2.0**: Service Recon, Headers, & Banner Grabbing
- [x] **v3.0**: Mass Scanning, CIDR, & Rate Limiting
- [x] **v4.0**: Script Engine (Vulnerability Checks) & CVE Lookup
- [x] **v5.0**: Interactive TUI Dashboard

---

## ⚠️ Disclaimer

**PortBlitz** is designed for security professionals and network administrators to audit their *own* networks.
*   Do not scan targets without authorization.
*   The developers are not responsible for misuse.

---

**Built with ❤️ by MIHx0 (Mizaz Haider) | Powered by The PenTrix**

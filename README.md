
# ⚡ PortBlitz v4.0

> **Ultra-fast, Asynchronous Port Scanner & Intelligence Engine**  
> *Built for speed, scale, and actionable security insights.*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![AsyncIO](https://img.shields.io/badge/Core-AsyncIO-purple)

---

## 📖 Overview

**PortBlitz** is a next-generation network scanner capable of scanning thousands of ports per second. Built on Python's `asyncio` framework, it combines the speed of compiled tools with the intelligence of modern vulnerability scanners.

**v4.0 "Intelligence" Release** introduces the **PortBlitz Script Engine (PBSE)**, **Tool Bridge**, and **CVE Lookup**, transforming it from a simple scanner into a smart reconnaissance weapon.

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **⚡ Blazing Fast** | Non-blocking async engine scans 1000+ ports/sec. |
| **🧠 Intelligence** | **CVE Lookup** & **Script Engine** for auto-vulnerability checks. |
| **🌉 Tool Bridge** | Auto-trigger **Nmap**, **Nuclei**, etc. on open ports. |
| **🌐 Mass Scale** | Scan CIDR ranges (`192.168.1.0/24`) & Target Lists (`-iL`). |
| **🛡️ Stealth/WAF** | **Rate Limiting** (`--rate`) & **WAF Evasion** (`--waf`). |
| **📊 Rich Reports** | outputs to **JSON**, **CSV**, and **HTML**. |

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

### 1. Intelligence Scan (v4.0 Recommended)
The ultimate recon scan: Scripts + CVE Mapping + WAF Evasion.
```bash
python portblitz.py target.com -p 1-1000 --scripts --vuln --waf
```

### 2. Auto-Bridge Mode
Automatically run `nmap -sV` or `nuclei` against interesting ports found by PortBlitz.
```bash
python portblitz.py 10.0.0.5 --bridge
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

## 🗺️ Roadmap

- [x] **v1.0**: Core Async Loop & HTML Reporting
- [x] **v2.0**: Service Recon, Headers, & Banner Grabbing
- [x] **v3.0**: Mass Scanning, CIDR, & Rate Limiting
- [ ] **v4.0**: Script Engine (Vulnerability Checks) & CVE Lookup
- [ ] **v5.0**: Interactive TUI Dashboard

---

## ⚠️ Disclaimer

**PortBlitz** is designed for security professionals and network administrators to audit their *own* networks.
*   Do not scan targets without authorization.
*   The developers are not responsible for misuse.

---

**Built with ❤️ by MIHx0 (Mizaz Haider) | Powered by The PenTrix**

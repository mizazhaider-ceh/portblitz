
# ⚡ PortBlitz v3.0

> **Ultra-fast, Asynchronous Port Scanner & Service Reconnaissance Tool**  
> *Built for speed, scale, and accuracy.*

![Python](https://img.shields.io/badge/Python-3.8%2B-blue) ![License](https://img.shields.io/badge/License-MIT-green) ![AsyncIO](https://img.shields.io/badge/Core-AsyncIO-purple)

---

## 📖 Overview

**PortBlitz** is a next-generation network scanner capable of scanning thousands of ports per second. Built on Python's `asyncio` framework, it offers the speed of compiled tools like Masscan with the flexibility and ease of use of Python.

**v3.0 "Mass Scale" Release** enhances the core engine with enterprise-grade features: multi-host scanning, CIDR network support, rate limiting, and deep service reconnaissance.

---

## 🚀 Key Features

| Feature | Description |
| :--- | :--- |
| **⚡ Blazing Fast** | Non-blocking async engine scans 1000+ ports/sec in pure Python. |
| **🧠 Smart Recon** | Auto-detects services (Apache, Nginx, SSH) & grabs banners. |
| **🌐 Mass Scale** | Scan entire subnets (`192.168.1.0/24`) or target lists (`-iL`). |
| **🛡️ Ops Safe** | Built-in **Rate Limiting** (`--rate`) and **Live Host Detection**. |
| **📊 Rich Reporting** | Outputs to **Colorized Console**, **JSON**, **CSV**, and **HTML**. |
| **🔍 Deep Insight** | Extracts HTTP Titles, Server headers, and SSL Certificate info. |

---

## 📥 Installation

PortBlitz requires **Python 3.8+**. No complex dependencies or C libraries needed.

```bash
git clone https://github.com/mizazhaider-ceh/portblitz.git
cd portblitz
# Ready to run!
```

---

## 💻 Usage

### 1. Basic Scan (Single Host)
Scan the most common 1000 ports on a target.
```bash
python portblitz.py example.com
```

### 2. Mass Scanning (v3.0 New!)
Scan a list of targets from a file or a CIDR range.
```bash
# Scan a target list
python portblitz.py -iL targets.txt --json

# Scan a network range
python portblitz.py 192.168.1.0/24 -p 80,443 --rate 100
```

### 3. Service Recon (v2.0)
Automatically grabs banners, HTTP titles, and detects service versions.
```bash
python portblitz.py 10.10.10.5 -p all
```
*Output Example:*
> `[+] Port 80  OPEN (http) | Title: Login Page | Server: Apache/2.4`  
> `[+] Port 22  OPEN (ssh)  | SSH-2.0-OpenSSH_8.2p1`

### 4. Rate Limiting & Stealth
Avoid WAFs and IPS bans by controlling packet speed.
```bash
# Limit to 50 packets per second
python portblitz.py target.com --rate 50
```

### 5. Data Export
Generate machine-readable reports for your pipeline.
```bash
python portblitz.py target.com --json --csv --output results/
```

---

## ⚙️ Command Line Options

```text
Target:
  target                IP (1.1.1.1), Domain (example.com), or CIDR (192.168.1.0/24)
  -iL, --input-list     Read list of targets from file

Scan Configuration:
  -p, --ports           Ports to scan: 'top' (default), 'all' (1-65535), or '80,443'
  -c, --concurrency     Max concurrent threads (default: 500)
  --rate                Rate limit in packets/s (default: Unlimited)
  -t, --timeout         Socket timeout in seconds (default: 1.0)
  --noping              Skip live host discovery (Force Scan)

Output:
  -o, --output          Output directory (default: 'reports')
  --json                Save results as JSON
  --csv                 Save results as CSV
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

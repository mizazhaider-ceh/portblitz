# PortBlitz ⚡

**Ultra-fast Async Port Scanner**

```
    ⚡ P O R T B L I T Z ⚡   v1.0
    Ultra-fast Async Port Scanner
```

**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

---

## 🚀 Overview

PortBlitz is a high-performance, asynchronous TCP port scanner written in Python. Designed for speed and reliability, it leverages non-blocking I/O to scan thousands of ports in seconds, making it a faster, lightweight alternative to standard threading scanners.

### Key Features (v2.0)
- **⚡ Async Architecture**: Uses Python's `asyncio` for high concurrency.
- **🕵️ Service Recon**: Detects service versions/sw using regex signatures.
- **� Banner Grabbing**: Captures raw headers from ports.
- **🌐 HTTP/SSL Analysis**: Extracts titles and generic SSL info.
- **� Data Export**: Save results to JSON and CSV.
- **🎨 HTML Reporting**: Beautiful, self-contained reports.

---

## 📥 Installation

```bash
git clone https://github.com/mizazhaider-ceh/portblitz.git
cd portblitz
```

---

## 💻 Usage

### Service Scan (New in v2.0)
```bash
python portblitz.py example.com
```

### Export Results
```bash
python portblitz.py 192.168.1.1 --json --csv
```

### High Speed Scan (1000 Concurrency)
```bash
python portblitz.py 192.168.1.1 -c 1000
```

### Specific Port Range
```bash
python portblitz.py example.com -p 1-5000
python portblitz.py example.com -p 80,443,8080
```

### All Ports (1-65535)
```bash
python portblitz.py example.com -p all
```

---

## 📊 Roadmap

We have an exciting roadmap ahead!

- **v1.0** (Completed): Async TCP scanning, HTML reports.
- **v2.0** (Completed): Service version detection, Banner grabbing, JSON/CSV.
- **v3.0**: CIDR range scanning & `uvloop` support.
- **v4.0**: Script Engine (vulnerability checks).
- **v5.0**: Interactive TUI Dashboard.

See [roadmap.md](roadmap.md) for full details.

---

## ⚠️ Legal Disclaimer

For authorized security testing and educational purposes only. The authors are not responsible for unauthorized use.

---

**Built with 💻 & ☕ by MIHx0**

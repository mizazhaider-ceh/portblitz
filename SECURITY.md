# Security Policy — PortBlitz

## Supported Versions

| Version | Supported |
|:--------|:----------|
| 5.0.x   | ✅ Active |
| < 5.0   | ❌ EOL    |

## Reporting a Vulnerability

If you discover a security vulnerability in PortBlitz, please report it responsibly:

1. **Do NOT** open a public GitHub issue
2. Email: **mizazhaider@proton.me** (or your preferred contact)
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Affected version(s)
   - Potential impact

### Response Timeline

| Stage | Timeframe |
|:------|:----------|
| Acknowledgement | 48 hours |
| Initial assessment | 5 business days |
| Fix release | 14 business days |

## Security Measures in v5.0

### XSS Prevention (Report Generation)
All user-controlled data injected into HTML reports is sanitised via `html.escape()`:
- Target hostnames/IPs
- Banner strings (attacker-controlled service responses)
- Script engine output
- Nmap/Nuclei bridge output

### Command Injection Prevention (Tool Bridge)
External tool execution in `modules/bridge.py` uses:
- `asyncio.create_subprocess_exec()` — **no shell interpolation**
- Strict regex whitelist (`^[A-Za-z0-9._:/\\-]+$`) on all target/URL inputs
- Port numbers cast to `int()` before use

### Input Validation
- CIDR networks validated via `ipaddress.ip_network()`
- Port ranges validated with `int()` casting and bounds checking
- File paths checked with `pathlib.Path.exists()` before access

### Exception Handling
All `except` clauses specify concrete exception types — no bare `except:` that could mask errors.

## Scope

This policy covers the PortBlitz scanner codebase. It does **not** cover:
- Third-party tools invoked via the bridge (Nmap, Nuclei)
- Targets scanned by end users
- Network infrastructure used during scanning

## Ethical Use

PortBlitz is designed for **authorised security testing only**. Users must:
- Obtain written permission before scanning any target
- Comply with all applicable laws and regulations
- Not use the tool for denial-of-service or unauthorized access

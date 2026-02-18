# PortBlitz — Portfolio Assessment

## Project: PortBlitz v5.0
**Category:** Offensive Security / Network Scanning Tool  
**Author:** Mizaz Haider (MIHx0)  
**Stack:** Python 3.8+ (stdlib only — zero dependencies)

---

## Executive Summary

PortBlitz is a high-performance asynchronous TCP port scanner with built-in intelligence capabilities. The v5.0 "Command Center" release demonstrates advanced Python async programming, security engineering, and tool-building skills through its CDN/WAF false-positive detection, interactive TUI, and extensible script engine.

---

## Technical Highlights

### 1. CDN/WAF False-Positive Detection (Unique Feature)
**Problem:** TCP connect scanners report every port as "OPEN" when scanning targets behind CDNs (Cloudflare, Akamai) because the load balancer accepts connections on all ports.

**Solution:** Canary-port probing — samples 8 random high ports (40000–64000) before the scan. If ≥75% accept TCP, the scanner switches to "verified-open" mode where each port must produce a meaningful banner to be reported.

**Impact:** Eliminates 60,000+ false positives on CDN-protected targets — a problem most open-source scanners don't address.

### 2. Security Hardening
| Vulnerability | Mitigation |
|:---|:---|
| XSS in HTML reports | `html.escape()` on all user-controlled data (banners, targets, script output) |
| Command injection in tool bridge | `create_subprocess_exec` (not shell) + regex input validation |
| Bare except clauses | Replaced with concrete exception types throughout |
| Filename injection | Target names sanitised with regex before filesystem use |

### 3. Architecture & Extensibility
- **Script Engine (PBSE):** Drop-in Python scripts in `scripts/` are auto-discovered and executed against matching ports/services
- **Tool Bridge:** Safe integration with Nmap and Nuclei via subprocess
- **Interactive TUI:** `cmd.Cmd`-based console with rich help system, session management, and feature toggles
- **Rate Limiter:** Token-bucket algorithm for stealth scanning

### 4. Testing
- **62 tests** covering scanner, false-positive detection, service detection, CVE lookup, XSS safety, command injection prevention, export, CLI, TUI, and live host discovery
- All tests pass on Python 3.8+

---

## Skills Demonstrated

| Skill | Evidence |
|:---|:---|
| **Async Programming** | `asyncio` semaphore pool, concurrent port scanning, async subprocess |
| **Security Engineering** | XSS prevention, command injection prevention, input validation |
| **Network Security** | TCP connect scanning, banner grabbing, SSL probing, CDN detection |
| **Software Architecture** | Clean module separation, pipeline pattern, extensible script engine |
| **Testing** | 62-test pytest suite with mocking, async tests, subprocess integration tests |
| **CLI/TUI Design** | argparse CLI + interactive console with rich help and session management |
| **DevSecOps** | SECURITY.md, responsible disclosure policy, security-focused code review |

---

## Code Metrics

| Metric | Value |
|:---|:---|
| Total Source Files | 24 |
| Test Coverage Areas | 13 test classes |
| External Dependencies | 0 (stdlib only) |
| Security Issues Fixed | 4 (XSS, injection, bare excepts, filename) |
| False Positive Reduction | ~99.9% on CDN targets |

---

## Future Development (v6.0 Roadmap)
- Scan profiles (stealth, loud, web-only)
- Result search and filtering in TUI
- Scan diff mode for configuration drift detection
- Cloud export (S3/Azure)
- Slack/Discord notifications on critical findings

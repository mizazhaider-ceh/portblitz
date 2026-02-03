# PortBlitz ⚡ - Implementation Roadmap

**Ultra-fast Async Port Scanner (Python)**  
**Built By:** MIHx0 (Mizaz Haider)  
**Powered By:** The PenTrix

---

## 📅 Evolution Roadmap

### **v1.0: The Foundation (MVP) [CURRENT TARGET]**
*Goal: Build a scanner that is significantly faster than standard `socket` loops.*
- **Core Engine:** `asyncio` based TCP Connect Scanner.
- **Input:** Single IP or Domain support.
- **Ports:** Scan Top 1000 common ports.
- **Branding:** MIHx0 / The PenTrix banner.
- **Output:**
    - Colorized terminal output.
    - **HTML Reporting:** Basic dashboard with open ports table (Included from start).

### **v2.0: Service Reconnaissance**
*Goal: Understand WHAT is running.*
- **Banner Grabbing:** Fetch service headers.
- **Service Detection:** Regex matching (Apache, Nginx, etc.).
- **HTTP Analysis:** Extract `<title>` and `Server` headers.
- **SSL/TLS Info:** Get Certificate Subject, Issuer, and Expiry.
- **Export:** JSON/CSV support.

### **v3.0: Scale & Mass Scanning**
*Goal: Handle entire networks efficiently.*
- **CIDR Support:** Scan ranges `192.168.1.0/24`.
- **Mass Input:** Read targets from file (`-iL targets.txt`).
- **Live Host Check:** Ping/TCP Sweep to skip dead hosts.
- **Rate Limiting:** Control packet rate (`--rate`) to avoid bans.
- **Smart Exclusion:** Exclude specific IPs/Ports.
- **Performance:** Structuring for multi-host storage.*
- **PBSE (PortBlitz Script Engine):** Simple plugin system.
- **CVE Lookup:** Auto-correlate versions with CVEs.

### **v5.0: The Command Center**
*Goal: Enterprise-grade usability.*
- **TUI Dashboard:** Interactive terminal interface.
- **Live Charts:** Packets/sec visualization.
- **Advanced HTML:** Interactive graphs and service hierarchy.

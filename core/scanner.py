"""
PortBlitz v5.0 — Core Scanner Engine

Async TCP connect scanner with false-positive detection for CDN/WAF targets.
"""

import asyncio
import random
import socket
from typing import List, Dict, Tuple, Set, Optional
from utils.display import Colors


# ---------------------------------------------------------------------------
# False-Positive Detection
# ---------------------------------------------------------------------------

async def _probe_canary_ports(target: str, timeout: float, count: int = 8) -> Tuple[int, int]:
    """
    Probe a set of random high ports that are almost never legitimately open.
    Returns (open_count, total_probed).
    If most of these are 'open', the target is behind a CDN/WAF catch-all.
    """
    # Pick random unlikely ports in the 40000-64000 range
    canary_ports = random.sample(range(40000, 64000), count)
    open_count = 0

    async def _check(port: int):
        nonlocal open_count
        try:
            _r, w = await asyncio.wait_for(
                asyncio.open_connection(target, port), timeout=timeout
            )
            w.close()
            await w.wait_closed()
            open_count += 1
        except Exception:
            pass

    await asyncio.gather(*[_check(p) for p in canary_ports])
    return open_count, count


async def detect_false_positives(target: str, timeout: float = 1.0, quiet: bool = False) -> bool:
    """
    Returns True if the target appears to be a CDN/WAF that accepts TCP on all ports.
    Probes 8 random high ports; if ≥6 are 'open' it's almost certainly a catch-all proxy.
    """
    open_count, total = await _probe_canary_ports(target, timeout)
    threshold = int(total * 0.75)  # 75 %

    if open_count >= threshold:
        if not quiet:
            print(f"\n  {Colors.YELLOW}⚠  CDN/WAF Detected — {open_count}/{total} canary ports accepted TCP.{Colors.RESET}")
            print(f"  {Colors.YELLOW}   Target is likely behind a reverse proxy (Cloudflare, Akamai, etc.).{Colors.RESET}")
            print(f"  {Colors.YELLOW}   Switching to verified-open mode (banner confirmation required).{Colors.RESET}\n")
        return True
    return False


# ---------------------------------------------------------------------------
# Port Scanner
# ---------------------------------------------------------------------------

async def scan_port(target: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    """
    Scan a single port via async TCP connect.  Returns (port, is_open).
    """
    try:
        _r, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return port, True
    except (asyncio.TimeoutError, ConnectionRefusedError, socket.gaierror, OSError):
        return port, False
    except Exception:
        return port, False


async def verify_port(target: str, port: int, timeout: float = 2.0) -> bool:
    """
    Secondary verification: connect and try to elicit a banner.
    If the connection succeeds but yields NO data and is NOT a well-known
    port, consider it a false positive.
    """
    WELL_KNOWN = {21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443,
                  445, 465, 587, 993, 995, 1433, 1723, 3306, 3389, 5432,
                  5900, 6379, 8080, 8443, 27017}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), timeout=timeout
        )
        # Send a small probe
        writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
        await writer.drain()

        data = b""
        try:
            data = await asyncio.wait_for(reader.read(512), timeout=timeout)
        except Exception:
            pass

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        # If we got meaningful bytes, it's a real service
        if data and len(data.strip()) > 0:
            return True

        # No data — trust the connection only for well-known ports
        return port in WELL_KNOWN

    except Exception:
        return False


async def scan_target(
    target: str,
    ports: List[int],
    concurrency: int = 500,
    timeout: float = 1.0,
    rate_limiter: Optional[object] = None,
    quiet: bool = False,
) -> List[Dict]:
    """
    Main scan function with automatic false-positive mitigation.
    """
    from core.banner import get_banner
    from core.service import detect_service

    results: List[Dict] = []
    semaphore = asyncio.Semaphore(concurrency)

    # --- Phase 0: CDN / WAF false-positive check ---
    needs_verification = await detect_false_positives(target, timeout, quiet)

    async def sem_scan(port: int):
        async with semaphore:
            if rate_limiter:
                await rate_limiter.acquire()

            p, is_open = await scan_port(target, port, timeout)
            if not is_open:
                return

            # If CDN detected, verify each port is genuinely open
            if needs_verification:
                genuinely_open = await verify_port(target, port, timeout)
                if not genuinely_open:
                    return  # False positive — skip

            # Banner grab & service detection
            info = await get_banner(target, port, timeout=2.0)
            banner_str = info.get("banner", "")

            # Fallback guess by port number
            initial_guess = "unknown"
            if port == 80:
                initial_guess = "http"
            elif port == 443:
                initial_guess = "https"
            elif port == 22:
                initial_guess = "ssh"
            elif port == 21:
                initial_guess = "ftp"
            elif port == 25:
                initial_guess = "smtp"
            elif port == 53:
                initial_guess = "dns"
            elif port == 3306:
                initial_guess = "mysql"
            elif port == 5432:
                initial_guess = "postgresql"
            elif port == 6379:
                initial_guess = "redis"
            elif port == 27017:
                initial_guess = "mongodb"
            elif port == 3389:
                initial_guess = "rdp"

            service = info.get("service", "unknown")
            if service == "unknown":
                service = detect_service(banner_str, initial_guess)

            # Display
            extra = ""
            if info.get("http_title"):
                extra = f" | Title: {info['http_title']}"
            elif info.get("ssl_info"):
                extra = f" | SSL: Yes"
            elif banner_str:
                clean = banner_str[:60].replace("\n", " ").replace("\r", "")
                extra = f" | {clean}"

            if not quiet:
                print(
                    f"  {Colors.GREEN}[+] Port {port:<5} OPEN  ({service}){Colors.RESET}"
                    f"{Colors.DIM}{extra}{Colors.RESET}"
                )

            results.append({
                "port": port,
                "service": service,
                "banner": banner_str,
                "http_title": info.get("http_title"),
                "ssl_info": info.get("ssl_info"),
            })

    await asyncio.gather(*[sem_scan(p) for p in ports])

    # Post-scan sanity check
    if not needs_verification and len(results) > len(ports) * 0.5 and len(ports) > 50:
        if not quiet:
            print(
                f"\n  {Colors.YELLOW}⚠  Warning: {len(results)}/{len(ports)} ports open "
                f"({len(results)*100//len(ports)}%). Results may include false positives.{Colors.RESET}"
            )

    return sorted(results, key=lambda x: x["port"])

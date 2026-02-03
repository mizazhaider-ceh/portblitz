
import asyncio
import socket
from typing import List, Dict, Tuple
from utils.display import Colors

async def scan_port(target: str, port: int, timeout: float = 1.0) -> Tuple[int, bool]:
    """
    Scan a single port using asyncio.
    Returns (port, is_open).
    """
    conn = None
    try:
        # High-performance async connection
        conn = asyncio.open_connection(target, port)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # If we reach here, port is OPEN
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

async def worker(target: str, ports: List[int], results: List[Dict], semaphore: asyncio.Semaphore, timeout: float):
    """
    Worker to process a queue of ports.
    """
    for port in ports:
        async with semaphore:
            p, is_open = await scan_port(target, port, timeout)
            if is_open:
                # Basic service guessing (common ports)
                service = "Unknown"
                if port == 80: service = "HTTP"
                elif port == 443: service = "HTTPS"
                elif port == 22: service = "SSH"
                elif port == 21: service = "FTP"
                elif port == 3306: service = "MySQL"
                elif port == 5432: service = "PostgreSQL"
                elif port == 6379: service = "Redis"
                elif port == 27017: service = "MongoDB"
                # Add more as needed or use a robust dict in v2.0
                
                print(f"  {Colors.GREEN}[+] Port {port:<5} OPEN  ({service}){Colors.RESET}")
                results.append({"port": port, "service": service})

async def scan_target(target: str, ports: List[int], concurrency: int = 500, timeout: float = 1.0) -> List[Dict]:
    """
    Main scanner orchestrator.
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)
    
    # Split work into chunks for cleaner progress (optional) or just blast all tasks
    # For v1.0, we'll create a single list of tasks but valid strategy is chunks
    
    tasks = []
    # Distribute ports among workers? 
    # Actually, iterate ports and spawn tasks bound by semaphore is easiest pattern
    
    
    # We want live output, so wrapping with semaphore in a worker function is better?
    # No, 'scan_port' is atomic. Let's create a wrapper that uses semaphore.
    
    async def sem_scan(port):
        async with semaphore:
            p, is_open = await scan_port(target, port, timeout)
            if is_open:
                # v2.0: Deep Service Recon
                from core.banner import get_banner
                from core.service import detect_service
                
                # Fetch banner & extra info
                info = await get_banner(target, port, timeout=2.0)
                banner_str = info.get("banner", "")
                
                # Basic guess fallback
                initial_guess = "unknown"
                if port == 80: initial_guess = "http"
                elif port == 443: initial_guess = "https"
                elif port == 22: initial_guess = "ssh"
                
                # Detect service using Regex + Banner
                service = info.get("service")
                if service == "unknown":
                    service = detect_service(banner_str, initial_guess)
                
                # Enhance display
                extra = ""
                if info.get("http_title"):
                    extra = f" | Title: {info['http_title']}"
                elif info.get("ssl_info"):
                    extra = f" | SSL: Yes"
                elif banner_str:
                    extra = f" | {banner_str[:40]}..."
                
                print(f"  {Colors.GREEN}[+] Port {port:<5} OPEN  ({service}){Colors.RESET}{Colors.DIM}{extra}{Colors.RESET}")
                
                results.append({
                    "port": port, 
                    "service": service,
                    "banner": banner_str,
                    "http_title": info.get("http_title"),
                    "ssl_info": info.get("ssl_info")
                })
    
    # Launch all
    await asyncio.gather(*[sem_scan(p) for p in ports])
    
    return sorted(results, key=lambda x: x['port'])

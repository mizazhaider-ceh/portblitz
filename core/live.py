
import asyncio
import sys
import subprocess
import socket
from typing import List
from utils.display import Colors

async def is_host_up(target: str, timeout: float = 1.0) -> bool:
    """
    Check if host is up using a quick TCP connect to common ports or ICMP if possible.
    ICMP usually requires root/admin, so we default to TCP Ping on port 80/443/22.
    """
    # 1. Try generic TCP connect on high-probability ports
    check_ports = [80, 443, 22, 135, 445] # Web + Admin ports
    
    for port in check_ports:
        try:
            conn = asyncio.open_connection(target, port)
            reader, writer = await asyncio.wait_for(conn, timeout=timeout / 2)
            writer.close()
            await writer.wait_closed()
            return True
        except (asyncio.TimeoutError, ConnectionRefusedError, OSError, socket.gaierror):
            pass
            
    # 2. If OS is Windows, we can try running system ping command (cheesy but works without raw sockets)
    # On Linux this is also viable for non-root users
    try:
        # -n 1 for windows, -c 1 for linux
        param = '-n' if sys.platform.lower() == 'win32' else '-c'
        cmd = ['ping', param, '1', str(target)]
        
        # Run in thread to avoid blocking loop
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL
        )
        await proc.wait()
        
        if proc.returncode == 0:
            return True
    except (OSError, FileNotFoundError):
        pass
        
    return False

async def filter_live_hosts(targets: List[str], concurrency: int = 100) -> List[str]:
    """
    Filter a list of targets, returning only those that appear online.
    """
    live_hosts = []
    sem = asyncio.Semaphore(concurrency)
    
    print(f"\n{Colors.CYAN}[*] Checking for live hosts ({len(targets)} targets)...{Colors.RESET}")
    
    async def check(t):
        async with sem:
            if await is_host_up(t):
                print(f"{Colors.GREEN}[+] Host Up: {t}{Colors.RESET}")
                live_hosts.append(t)
                
    await asyncio.gather(*[check(t) for t in targets])
    
    print(f"{Colors.BOLD}[*] Live Check Complete: {len(live_hosts)}/{len(targets)} hosts up.{Colors.RESET}\n")
    return live_hosts

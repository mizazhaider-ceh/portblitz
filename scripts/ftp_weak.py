
import asyncio
from typing import Dict

# Metadata
TARGET_PORTS = [21]
TARGET_SERVICES = ["ftp"]

async def run(target: str, port: int, service_info: Dict) -> str:
    """
    Checks for Anonymous FTP Login.
    """
    try:
        reader, writer = await asyncio.open_connection(target, port)
        
        # Read banner
        try:
            await asyncio.wait_for(reader.read(1024), timeout=2.0)
        except (asyncio.TimeoutError, ConnectionError):
            pass
            
        # Send USER anonymous
        writer.write(b"USER anonymous\r\n")
        await writer.drain()
        resp_user = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        
        # Send PASS anonymous@
        writer.write(b"PASS anonymous@\r\n")
        await writer.drain()
        resp_pass = await asyncio.wait_for(reader.read(1024), timeout=2.0)
        
        writer.close()
        await writer.wait_closed()
        
        response = resp_pass.decode().lower()
        if "230" in response or "login successful" in response:
            return "VULN: Anonymous FTP Allowed"
            
    except Exception:
        pass
        
    return None

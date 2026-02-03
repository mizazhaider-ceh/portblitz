
import asyncio
from typing import Dict

TARGET_PORTS = [80, 8080, 8000]
TARGET_SERVICES = ["http"]

async def run(target: str, port: int, service_info: Dict) -> str:
    """
    Checks for basic HTTP vulnerabilities:
    - Directory Listing (Index of /)
    - Missing Security Headers
    """
    findings = []
    
    # We rely on the initial banner grab if possible, but here we do a specific GET /
    try:
        request = f"GET / HTTP/1.1\r\nHost: {target}\r\nUser-Agent: PortBlitz/4.0\r\nConnection: close\r\n\r\n"
        
        reader, writer = await asyncio.open_connection(target, port)
        writer.write(request.encode())
        await writer.drain()
        
        data = await asyncio.wait_for(reader.read(4096), timeout=3.0)
        writer.close()
        await writer.wait_closed()
        
        response = data.decode(errors='ignore')
        
        # Check Directory Listing
        if "Index of /" in response:
            findings.append("Directory Listing Enabled")
            
        # Check Missing Headers (Basic check)
        headers_lower = response.lower()
        if "x-frame-options" not in headers_lower:
            findings.append("Missing X-Frame-Options")
            
        if findings:
            return " | ".join(findings)
            
    except Exception:
        pass
        
    return None

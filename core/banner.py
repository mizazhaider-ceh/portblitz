
import asyncio
import ssl
from typing import Dict, Tuple

async def get_banner(target: str, port: int, timeout: float = 2.0) -> Dict:
    """
    Connect to a port and retrieve the banner, HTTP title, or SSL info.
    """
    info = {
        "banner": None,
        "service": "unknown",
        "http_title": None,
        "ssl_info": None
    }
    
    # Heuristic for SSL ports (standard)
    is_ssl_port = port in [443, 8443, 993, 995, 465]
    
    try:
        # 1. Try SSL Connection first if likely SSL
        if is_ssl_port:
             info.update(await probe_ssl(target, port, timeout))
             if info["service"] != "unknown":
                 return info
        
        # 2. Try Standard TCP Connection
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(target, port), 
            timeout=timeout
        )
        
        # Send a generic probe to trigger response
        # HTTP-like probe works for many services (they either respond or error out with a banner)
        probe = b"HEAD / HTTP/1.0\r\n\r\n"
        writer.write(probe)
        await writer.drain()
        
        # Read raw banner
        raw_data = await asyncio.wait_for(reader.read(1024), timeout=timeout)
        data_str = raw_data.decode('utf-8', errors='ignore').strip()
        
        if data_str:
            info["banner"] = data_str
            # Basic HTTP Title Check
            if "HTTP/" in data_str and "<title>" in data_str.lower():
                import re
                m = re.search(r'<title>(.*?)</title>', data_str, re.IGNORECASE)
                if m:
                    info["http_title"] = m.group(1).strip()
                info["service"] = "http"
            
            # Check SSH
            elif "SSH-" in data_str:
                info["service"] = "ssh"
            
            # Check FTP
            elif "220" in data_str and "FTP" in data_str:
                info["service"] = "ftp"
                
            # Check SMTP
            elif "220" in data_str and "SMTP" in data_str:
                info["service"] = "smtp"
                
        writer.close()
        await writer.wait_closed()
        
    except Exception:
        pass
        
    return info

async def probe_ssl(target: str, port: int, timeout: float) -> Dict:
    res = {}
    try:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        
        conn = asyncio.open_connection(target, port, ssl=ssl_ctx)
        reader, writer = await asyncio.wait_for(conn, timeout=timeout)
        
        # Get cert info
        try:
            cert = writer.get_extra_info('ssl_object').getpeercert(binary_form=True)
            # We would need to parse binary cert or use getpeercert() without binary_form if verified.
            # But with CERT_NONE, getpeercert() returns empty dict usually unless binary_form=True?
            # actually getpeercert() returns nothing if validation is off in some python versions.
            # Let's rely on basic existence for now to mark as HTTPS
            res["service"] = "https"
            res["ssl_info"] = "Present (Details parsed in v2.1)"
            
            # Try to read HTTP banner over SSL
            writer.write(b"HEAD / HTTP/1.0\r\n\r\n")
            await writer.drain()
            raw = await reader.read(1024)
            decoded = raw.decode('utf-8', errors='ignore')
            
            if decoded:
                res["banner"] = decoded
                import re
                m = re.search(r'<title>(.*?)</title>', decoded, re.IGNORECASE)
                if m:
                    res["http_title"] = m.group(1).strip()
                    
        except Exception:
            pass
            
        writer.close()
        await writer.wait_closed()
    except Exception:
        pass
        
    return res


import asyncio
import shutil
import shlex
from typing import Optional
from utils.display import Colors

class ToolBridge:
    """
    Bridge to external security tools (Nmap, Nuclei, etc.).
    Checks availability and runs them against targets.
    """
    
    @staticmethod
    def is_installed(tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    @staticmethod
    async def run_nmap_version(target: str, port: int) -> str:
        """Runs nmap usage: nmap -sV -p <port> <target>"""
        if not ToolBridge.is_installed("nmap"):
            return "Nmap not installed"
            
        cmd = f"nmap -sV -Pn -n -p {port} {target}"
        return await ToolBridge._run_command(cmd)

    @staticmethod
    async def run_nuclei(target: str, port: int) -> str:
        """Runs nuclei usage: nuclei -u http://target:port"""
        if not ToolBridge.is_installed("nuclei"):
            return "Nuclei not installed"
            
        # Nuclei usually targets HTTP/S
        url = f"http://{target}:{port}" if port not in [443, 8443] else f"https://{target}:{port}"
        
        # Fast scan, no interaction
        cmd = f"nuclei -u {url} -silent -no-interact"
        return await ToolBridge._run_command(cmd)

    @staticmethod
    async def _run_command(command: str) -> str:
        try:
            process = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            output = stdout.decode().strip()
            if not output and stderr:
                return f"Error: {stderr.decode().strip()}"
            return output
        except Exception as e:
            return f"Execution failed: {str(e)}"

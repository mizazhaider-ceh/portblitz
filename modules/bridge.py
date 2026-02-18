"""
PortBlitz v5.0 — External Tool Bridge

Safely delegates to Nmap / Nuclei via subprocess (no shell injection).
"""

import asyncio
import re
import shutil
from utils.display import Colors

# Strict whitelist for target strings to prevent command injection
_SAFE_TARGET = re.compile(r"^[A-Za-z0-9._:/\-]+$")


def _validate(value: str, label: str) -> str:
    """Raise ValueError if *value* contains shell-unsafe characters."""
    if not _SAFE_TARGET.match(value):
        raise ValueError(f"Unsafe {label}: {value!r}")
    return value


class ToolBridge:
    """
    Bridge to external security tools (Nmap, Nuclei, etc.).
    Uses create_subprocess_exec (NOT shell) for safety.
    """

    @staticmethod
    def is_installed(tool_name: str) -> bool:
        return shutil.which(tool_name) is not None

    @staticmethod
    async def run_nmap_version(target: str, port: int) -> str:
        """Run: nmap -sV -Pn -n -p <port> <target>"""
        if not ToolBridge.is_installed("nmap"):
            return "Nmap not installed"

        _validate(target, "target")
        return await ToolBridge._run_command(
            "nmap", "-sV", "-Pn", "-n", "-p", str(int(port)), target
        )

    @staticmethod
    async def run_nuclei(target: str, port: int) -> str:
        """Run: nuclei -u http(s)://target:port -silent -no-interact"""
        if not ToolBridge.is_installed("nuclei"):
            return "Nuclei not installed"

        _validate(target, "target")
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}:{int(port)}"
        return await ToolBridge._run_command(
            "nuclei", "-u", url, "-silent", "-no-interact"
        )

    @staticmethod
    async def _run_command(*args: str) -> str:
        """Execute an external tool safely (no shell)."""
        try:
            process = await asyncio.create_subprocess_exec(
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await process.communicate()

            output = stdout.decode(errors="replace").strip()
            if not output and stderr:
                return f"Error: {stderr.decode(errors='replace').strip()}"
            return output
        except Exception as e:
            return f"Execution failed: {e}"

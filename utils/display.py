
import sys

class Colors:
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    BG_BLUE = '\033[44m'
    RESET = '\033[0m'

VERSION = "3.0"

def print_banner():
    """Print the PortBlitz banner."""
    print(f"""
{Colors.YELLOW}
    ⚡ P O R T B L I T Z ⚡   {Colors.CYAN}v{VERSION}{Colors.YELLOW}
    Ultra-fast Async Port Scanner
{Colors.RESET}
    {Colors.GREEN}===================================================={Colors.RESET}
    {Colors.MAGENTA}◆ Built By  :{Colors.RESET} {Colors.BOLD}MIHx0{Colors.RESET} (Mizaz Haider)
    {Colors.MAGENTA}◆ Powered By:{Colors.RESET} {Colors.BOLD}The PenTrix{Colors.RESET}
    {Colors.GREEN}===================================================={Colors.RESET}
""")

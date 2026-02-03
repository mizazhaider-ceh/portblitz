
import cmd
import sys
import asyncio
from types import SimpleNamespace
from utils.display import Colors, VERSION, print_banner
from core.orchestrator import ScanOrchestrator
from utils.charts import print_chart
from utils.net import parse_targets

class PortBlitzConsole(cmd.Cmd):
    intro = f"""
{Colors.CYAN}    ⚡ PortBlitz v{VERSION} Command Center ⚡{Colors.RESET}
    Type 'help' or '?' for commands. 'exit' to quit.
    """
    prompt = f"{Colors.BOLD}portblitz > {Colors.RESET}"

    def __init__(self):
        super().__init__()
        # Default Session State
        self.target_list = []
        self.target_str = ""
        self.ports_str = "top"
        self.options = SimpleNamespace(
            concurrency=500,
            timeout=1.0,
            rate=0,
            scripts=False,
            vuln=False,
            waf=False,
            bridge=False,
            noping=False,
            output="reports",
            json=False,
            csv=False
        )

    def do_set(self, arg):
        """Set options. Usage: set <option> <value>
        Options: target, ports, rate, scripts, vuln, bridge, waf"""
        if not arg:
            print(f"{Colors.RED}Usage: set <option> <value>{Colors.RESET}")
            return
            
        # Robust parsing: handle "target = ip" or "vuln check true"
        parts = arg.split()
        
        # Remove '=' if user typed it (e.g., set target = 1.2.3.4)
        if "=" in parts:
            parts.remove("=")
            
        if len(parts) < 2:
             print(f"{Colors.RED}Usage: set <option> <value>{Colors.RESET}")
             return

        key = parts[0].lower()
        val = parts[1].lower() # Default value logic
        
        # Special case: re-join value if it was meant to be one string but got split?
        # Ideally target/ports are single strings.
        
        if key == "target":
            self.target_str = parts[1] # Take the raw second token
            try:
                self.target_list = parse_targets(self.target_str)
                print(f"{Colors.GREEN}[+] Target set to: {self.target_str} ({len(self.target_list)} hosts){Colors.RESET}")
            except Exception as e:
                print(f"{Colors.RED}[!] Invalid target: {e}{Colors.RESET}")
                self.target_list = [] # Reset on error
                
        elif key == "ports":
            self.ports_str = parts[1]
            print(f"{Colors.GREEN}[+] Ports set to: {self.ports_str}{Colors.RESET}")
            
        elif key == "rate":
            try:
                self.options.rate = int(parts[1])
                print(f"{Colors.GREEN}[+] Rate limit set to: {self.options.rate}{Colors.RESET}")
            except ValueError:
                print(f"{Colors.RED}[!] Rate must be an integer{Colors.RESET}")
            
        # Boolean Flags
        elif key in ["scripts", "vuln", "waf", "bridge", "noping"]:
            # Check the last part or the part after key for 'on'/'true'
            # e.g. "set vuln check true" -> key=vuln, parts=['vuln', 'check', 'true']
            # We want the LAST token usually if it's "true"/"on"
            
            check_val = parts[-1].lower()
            if check_val in ["on", "true", "1", "yes", "enable"]:
                state = True
            elif check_val in ["off", "false", "0", "no", "disable"]:
                state = False
            else:
                 # Fallback: maybe they just typed "set vuln" (implying on?)
                 # For safety, require explicit value
                 print(f"{Colors.YELLOW}[!] Use 'on' or 'off'. Example: set {key} on{Colors.RESET}")
                 return
                 
            setattr(self.options, key, state)
            print(f"{Colors.GREEN}[+] {key} set to: {'ON' if state else 'OFF'}{Colors.RESET}")
            
        else:
            print(f"{Colors.YELLOW}[!] Unknown option: {key}{Colors.RESET}")


    def do_clear(self, arg):
        """Clear the console screen."""
        print("\033c", end="")
        print_banner()
        print(f"\n{Colors.CYAN}    ⚡ PortBlitz v{VERSION} Command Center ⚡{Colors.RESET}\n")

    def do_cls(self, arg):
        """Alias for clear."""
        self.do_clear(arg)

    def do_show(self, arg):
        """Show current configuration."""
        print(f"\n{Colors.BOLD}--- Session Configuration ---{Colors.RESET}")
        print(f"Target     : {self.target_str if self.target_str else 'Not Set'} ({len(self.target_list)} hosts)")
        print(f"Ports      : {self.ports_str}")
        print(f"Rate Limit : {self.options.rate}")
        print(f"Scripts    : {'ON' if self.options.scripts else 'OFF'}")
        print(f"Vuln Check : {'ON' if self.options.vuln else 'OFF'}")
        print(f"Tool Bridge: {'ON' if self.options.bridge else 'OFF'}")
        print(f"WAF Evasion: {'ON' if self.options.waf else 'OFF'}")
        print("")

    def do_run(self, arg):
        """Run the scan with current configuration."""
        if not self.target_list:
            print(f"{Colors.RED}[!] No targets set. Use 'set target <ip>'{Colors.RESET}")
            return
            
        # Parse Ports Logic
        ports = []
        if self.ports_str == "top":
            from portblitz import STANDARD_PORTS
            ports = STANDARD_PORTS
        elif self.ports_str == "all":
            ports = list(range(1, 65536))
        elif "-" in self.ports_str:
            try:
                start, end = map(int, self.ports_str.split("-"))
                ports = list(range(start, end + 1))
            except:
                print(f"{Colors.RED}[!] Invalid port range{Colors.RESET}")
                return
        else:
            try:
                ports = [int(p) for p in self.ports_str.split(",")]
            except:
                print(f"{Colors.RED}[!] Invalid port list{Colors.RESET}")
                return

        print(f"\n{Colors.CYAN}🚀 Launching Scan against {len(self.target_list)} hosts...{Colors.RESET}")
        
        # Run Orchestrator
        try:
            if sys.platform == 'win32':
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
            orchestrator = ScanOrchestrator(self.target_list, ports, self.options)
            scan_stats = asyncio.run(orchestrator.run())
            
            if scan_stats:
                print_chart(scan_stats, title="Open Ports per Host")
            
        except Exception as e:
            print(f"{Colors.RED}[!] Scan Error: {e}{Colors.RESET}")

    def do_exit(self, arg):
        """Exit the console."""
        print("Goodbye!")
        return True

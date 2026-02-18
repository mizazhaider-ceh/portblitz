"""
PortBlitz v5.0 — Interactive Command Center

Professional TUI with rich help, session management, and inline guidance.
"""

import cmd
import sys
import asyncio
from types import SimpleNamespace
from utils.display import Colors, VERSION, print_banner
from core.orchestrator import ScanOrchestrator
from utils.charts import print_chart
from utils.net import parse_targets


# ─────────────────────────────────────────────────────────────────
# Helper: formatted option table for `show`
# ─────────────────────────────────────────────────────────────────

def _bool_badge(val: bool) -> str:
    if val:
        return f"{Colors.GREEN}ON{Colors.RESET}"
    return f"{Colors.RED}OFF{Colors.RESET}"


def _section(title: str) -> str:
    return f"\n  {Colors.CYAN}{Colors.BOLD}─── {title} ───{Colors.RESET}"


# ─────────────────────────────────────────────────────────────────
# Console
# ─────────────────────────────────────────────────────────────────

class PortBlitzConsole(cmd.Cmd):
    intro = f"""
{Colors.CYAN}    ⚡ PortBlitz v{VERSION} — Interactive Command Center ⚡{Colors.RESET}
    {Colors.DIM}Type 'help' for command reference  ·  'show' to view config  ·  'exit' to quit{Colors.RESET}
    """
    prompt = f"{Colors.BOLD}{Colors.CYAN}portblitz{Colors.RESET}{Colors.BOLD} ❯ {Colors.RESET}"

    def __init__(self):
        super().__init__()
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
            csv=False,
        )

    # ──────── HELP ────────

    def do_help(self, arg):
        """Display command reference and usage examples."""
        if arg:
            # Dispatch to per-command help
            try:
                func = getattr(self, "help_" + arg)
                func()
            except AttributeError:
                try:
                    doc = getattr(self, "do_" + arg).__doc__
                    if doc:
                        print(f"\n  {doc}\n")
                    else:
                        print(f"  {Colors.YELLOW}No help for '{arg}'{Colors.RESET}")
                except AttributeError:
                    print(f"  {Colors.RED}Unknown command: {arg}{Colors.RESET}")
            return

        print(f"""
{_section('COMMANDS')}

  {Colors.GREEN}set{Colors.RESET} <option> <value>   Set a scan option (see 'help set')
  {Colors.GREEN}show{Colors.RESET}                   Display current session configuration
  {Colors.GREEN}run{Colors.RESET}                    Execute the scan with current settings
  {Colors.GREEN}clear{Colors.RESET} / {Colors.GREEN}cls{Colors.RESET}            Clear the screen
  {Colors.GREEN}help{Colors.RESET} [command]          Show this reference or help for a command
  {Colors.GREEN}exit{Colors.RESET}                   Quit PortBlitz

{_section('SCAN OPTIONS  (set <option> <value>)')}

  {Colors.BOLD}target{Colors.RESET}   IP, domain, or CIDR          {Colors.DIM}set target 192.168.1.0/24{Colors.RESET}
  {Colors.BOLD}ports{Colors.RESET}    top | all | range | csv      {Colors.DIM}set ports 1-1000{Colors.RESET}
  {Colors.BOLD}rate{Colors.RESET}     Packets/sec (0 = unlimited)  {Colors.DIM}set rate 1000{Colors.RESET}

{_section('FEATURE TOGGLES  (set <flag> on|off)')}

  {Colors.BOLD}scripts{Colors.RESET}  PortBlitz Script Engine      {Colors.DIM}set scripts on{Colors.RESET}
  {Colors.BOLD}vuln{Colors.RESET}     CVE Lookup & Vuln Checks     {Colors.DIM}set vuln on{Colors.RESET}
  {Colors.BOLD}bridge{Colors.RESET}   Auto Nmap / Nuclei bridge    {Colors.DIM}set bridge on{Colors.RESET}
  {Colors.BOLD}waf{Colors.RESET}      WAF Evasion (random UA/delay) {Colors.DIM}set waf on{Colors.RESET}
  {Colors.BOLD}noping{Colors.RESET}   Skip live-host discovery      {Colors.DIM}set noping on{Colors.RESET}

{_section('QUICK START')}

  {Colors.DIM}portblitz ❯{Colors.RESET} set target scanme.nmap.org
  {Colors.DIM}portblitz ❯{Colors.RESET} set ports 1-1000
  {Colors.DIM}portblitz ❯{Colors.RESET} set vuln on
  {Colors.DIM}portblitz ❯{Colors.RESET} run
""")

    def help_set(self):
        print(f"""
  {Colors.BOLD}set{Colors.RESET} <option> <value>

  {Colors.GREEN}Targets:{Colors.RESET}
    set target 192.168.1.1       Single IP
    set target example.com       Domain
    set target 10.0.0.0/24       CIDR network

  {Colors.GREEN}Ports:{Colors.RESET}
    set ports top                Top ~1050 ports (default)
    set ports all                All 65535 ports
    set ports 1-1000             Range
    set ports 22,80,443          Comma-separated

  {Colors.GREEN}Toggles (on/off):{Colors.RESET}
    set scripts on               Enable PBSE Script Engine
    set vuln on                  Enable CVE + vuln checks
    set bridge on                Enable Nmap/Nuclei bridge
    set waf on                   WAF evasion mode
    set noping on                Skip live-host check

  {Colors.GREEN}Tuning:{Colors.RESET}
    set rate 1000                Rate limit (packets/sec)
""")

    def help_run(self):
        print(f"""
  {Colors.BOLD}run{Colors.RESET}

  Execute a scan with the current session configuration.
  Requires a target to be set first ({Colors.DIM}set target <host>{Colors.RESET}).
""")

    # ──────── SET ────────

    def do_set(self, arg):
        """Set scan options. Usage: set <option> <value>"""
        if not arg:
            self.help_set()
            return

        parts = arg.split()
        if "=" in parts:
            parts.remove("=")

        if len(parts) < 2:
            print(f"  {Colors.RED}Usage: set <option> <value>{Colors.RESET}")
            return

        key = parts[0].lower()
        val = parts[1]

        if key == "target":
            self.target_str = val
            try:
                self.target_list = parse_targets(self.target_str)
                print(f"  {Colors.GREEN}[+] Target → {self.target_str}  ({len(self.target_list)} host{'s' if len(self.target_list) != 1 else ''}){Colors.RESET}")
            except Exception as e:
                print(f"  {Colors.RED}[!] Invalid target: {e}{Colors.RESET}")
                self.target_list = []

        elif key == "ports":
            self.ports_str = val
            print(f"  {Colors.GREEN}[+] Ports → {self.ports_str}{Colors.RESET}")

        elif key == "rate":
            try:
                self.options.rate = int(val)
                print(f"  {Colors.GREEN}[+] Rate limit → {self.options.rate} pkt/s{Colors.RESET}")
            except ValueError:
                print(f"  {Colors.RED}[!] Rate must be an integer{Colors.RESET}")

        elif key in ("scripts", "vuln", "waf", "bridge", "noping", "json", "csv"):
            check_val = parts[-1].lower()
            if check_val in ("on", "true", "1", "yes", "enable"):
                state = True
            elif check_val in ("off", "false", "0", "no", "disable"):
                state = False
            else:
                print(f"  {Colors.YELLOW}[!] Use on/off. Example: set {key} on{Colors.RESET}")
                return
            setattr(self.options, key, state)
            print(f"  {Colors.GREEN}[+] {key} → {_bool_badge(state)}{Colors.RESET}")

        else:
            print(f"  {Colors.YELLOW}[!] Unknown option: {key}  (type 'help set'){Colors.RESET}")

    # ──────── SHOW ────────

    def do_show(self, arg):
        """Display current session configuration."""
        t = self.target_str or f"{Colors.DIM}(not set){Colors.RESET}"
        hosts = len(self.target_list)

        print(f"""
{_section('SESSION CONFIGURATION')}

  {Colors.BOLD}Target     :{Colors.RESET} {t}  ({hosts} host{'s' if hosts != 1 else ''})
  {Colors.BOLD}Ports      :{Colors.RESET} {self.ports_str}
  {Colors.BOLD}Concurrency:{Colors.RESET} {self.options.concurrency}
  {Colors.BOLD}Timeout    :{Colors.RESET} {self.options.timeout}s
  {Colors.BOLD}Rate Limit :{Colors.RESET} {self.options.rate if self.options.rate else 'Unlimited'}

{_section('FEATURES')}

  Scripts (PBSE)    {_bool_badge(self.options.scripts)}
  CVE / Vuln Check  {_bool_badge(self.options.vuln)}
  Tool Bridge       {_bool_badge(self.options.bridge)}
  WAF Evasion       {_bool_badge(self.options.waf)}
  Skip Ping         {_bool_badge(self.options.noping)}

{_section('OUTPUT')}

  HTML Report       {_bool_badge(True)}   {Colors.DIM}(always){Colors.RESET}
  JSON Export        {_bool_badge(self.options.json)}
  CSV  Export        {_bool_badge(self.options.csv)}
""")

    # ──────── RUN ────────

    def do_run(self, arg):
        """Execute the scan with current settings."""
        if not self.target_list:
            print(f"  {Colors.RED}[!] No target set. Use: set target <host>{Colors.RESET}")
            return

        # Parse ports
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
            except ValueError:
                print(f"  {Colors.RED}[!] Invalid port range{Colors.RESET}")
                return
        else:
            try:
                ports = [int(p) for p in self.ports_str.split(",")]
            except ValueError:
                print(f"  {Colors.RED}[!] Invalid port list{Colors.RESET}")
                return

        print(f"\n  {Colors.CYAN}🚀 Scanning {len(self.target_list)} host(s) · {len(ports)} ports{Colors.RESET}\n")

        try:
            if sys.platform == "win32":
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

            orchestrator = ScanOrchestrator(self.target_list, ports, self.options)
            scan_stats = asyncio.run(orchestrator.run())

            if scan_stats:
                print_chart(scan_stats, title="Open Ports per Host")

        except KeyboardInterrupt:
            print(f"\n  {Colors.YELLOW}[!] Scan interrupted.{Colors.RESET}")
        except Exception as e:
            print(f"  {Colors.RED}[!] Scan error: {e}{Colors.RESET}")

    # ──────── UTILITY ────────

    def do_clear(self, arg):
        """Clear the console screen."""
        print("\033c", end="")
        print_banner()
        print(self.intro)

    def do_cls(self, arg):
        """Alias for clear."""
        self.do_clear(arg)

    def do_exit(self, arg):
        """Quit PortBlitz."""
        print(f"  {Colors.DIM}Goodbye!{Colors.RESET}")
        return True

    do_quit = do_exit
    do_EOF = do_exit

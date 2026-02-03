
#!/usr/bin/env python3
import asyncio
import argparse
import sys
import time
from pathlib import Path

# Add parent path to find modules
sys.path.insert(0, str(Path(__file__).parent))

from core.scanner import scan_target
from utils.display import print_banner, Colors
from utils.report import generate_report

# Common Top 1000 ports (truncated for v1.0 MVP, full list can be loaded from file later)
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 
    1723, 3306, 3389, 5900, 8080, 8443, 27017, 6379, 5432, 5000, 8000, 8888
] 
# (In a real tool we'd ranges(1, 1024) or similar. 
# Let's generate a range for v1.0 standard scan)
STANDARD_PORTS = list(range(1, 1025)) + TOP_PORTS
STANDARD_PORTS = sorted(list(set(STANDARD_PORTS)))

def main():
    parser = argparse.ArgumentParser(description="PortBlitz - Ultra-fast Async Port Scanner")
    parser.add_argument("target", nargs='?', help="Target IP, Domain, or CIDR")
    parser.add_argument("-iL", "--input-list", help="Input from list of hosts/networks")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrency level (default: 500)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout (default: 1.0s)")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1000 or 'all')", default="top")
    parser.add_argument("-o", "--output", help="Output directory for reports", default="reports")
    parser.add_argument("--rate", type=int, default=0, help="Rate limit (packets/s), 0=unlimited")
    parser.add_argument("--noping", action="store_true", help="Skip live host discovery")
    parser.add_argument("--json", action="store_true", help="Export to JSON")
    parser.add_argument("--csv", action="store_true", help="Export to CSV")
    parser.add_argument("--scripts", action="store_true", help="Enable PortBlitz Script Engine (PBSE)")
    parser.add_argument("--vuln", action="store_true", help="Enable CVE Lookup & Vulnerability Checks")
    parser.add_argument("--waf", action="store_true", help="Enable WAF Evasion (Random UA / Delays)")
    parser.add_argument("--bridge", action="store_true", help="Enable Tool Bridge (Auto-trigger Nmap/Nuclei)")
    parser.add_argument("-i", "--interactive", action="store_true", help="Enter Interactive Command Center (v5.0)")
    
    args = parser.parse_args()
    
    # Imports
    from utils.net import parse_targets, load_targets_from_file
    from utils.display import VERSION
    from core.orchestrator import ScanOrchestrator
    
    print_banner()

    # 0. Interactive Mode Check
    if args.interactive:
        from core.console import PortBlitzConsole
        try:
            PortBlitzConsole().cmdloop()
        except KeyboardInterrupt:
            print(f"\n{Colors.YELLOW}[!] Exiting Console.{Colors.RESET}")
        sys.exit(0)
    
    # 1. Load Targets
    targets = []
    if args.input_list:
        try:
            targets.extend(load_targets_from_file(args.input_list))
        except FileNotFoundError as e:
            print(f"{Colors.RED}[!] {e}{Colors.RESET}")
            sys.exit(1)
            
    if args.target:
        targets.extend(parse_targets(args.target))
    targets = list(set(targets))
    
    if not targets:
        print(f"{Colors.RED}[!] No targets specified. Use target arg, -iL, or -i for interactive mode.{Colors.RESET}")
        parser.print_help()
        sys.exit(1)
    
    # 2. Parse Ports
    ports = []
    if args.ports == "top":
        ports = STANDARD_PORTS
    elif args.ports == "all":
        ports = list(range(1, 65536))
    elif "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
    else:
        ports = [int(p) for p in args.ports.split(",")]

    port_count_str = f"{len(ports)} ports" if len(ports) < 20 else f"{len(ports)} ports (Range/Top)"
    print(f"{Colors.BOLD}Targets :{Colors.RESET} {len(targets)} hosts")
    print(f"{Colors.BOLD}Ports   :{Colors.RESET} {port_count_str}")
    print(f"{Colors.BOLD}Features:{Colors.RESET} Scans: {args.concurrency}th | Rate: {args.rate if args.rate else 'Unlim'} | Scripts: {'ON' if args.scripts else 'OFF'} | Vuln: {'ON' if args.vuln else 'OFF'}")
    print(f"{Colors.DIM}{'-'*40}{Colors.RESET}\n")

    # 3. Run Orchestrator
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        orchestrator = ScanOrchestrator(targets, ports, args)
        asyncio.run(orchestrator.run())
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()

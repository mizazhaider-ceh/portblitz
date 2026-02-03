
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
    
    args = parser.parse_args()
    
    # Imports for v3.0
    from utils.net import parse_targets, load_targets_from_file
    from core.live import filter_live_hosts
    from core.rate import RateLimiter
    from utils.display import VERSION
    
    print_banner()
    
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
        
    targets = list(set(targets)) # Deduplicate
    
    if not targets:
        print(f"{Colors.RED}[!] No targets specified. Use target arg or -iL{Colors.RESET}")
        parser.print_help()
        sys.exit(1)

    # ... (Previous args parsing code remains similar, but we restructure execution)
    
    # 2. Parse Ports (Sync)
    ports = []
    if args.ports == "top":
        ports = STANDARD_PORTS
        port_desc = "Top 1000+ (Common)"
    elif args.ports == "all":
        ports = list(range(1, 65536))
        port_desc = "ALL (1-65535) - ⚠️ High Traffic"
    elif "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = list(range(start, end + 1))
        port_desc = f"Range {start}-{end}"
    else:
        ports = [int(p) for p in args.ports.split(",")]
        port_desc = f"Specific ({len(ports)} ports)"

    print(f"{Colors.BOLD}Targets:{Colors.RESET} {len(targets)} hosts")
    print(f"{Colors.BOLD}Ports  :{Colors.RESET} {port_desc}")
    print(f"{Colors.BOLD}Speed  :{Colors.RESET} {args.concurrency} threads (Rate: {args.rate if args.rate > 0 else 'Unlimited'} pkts/s)")
    print(f"{Colors.DIM}{'-'*40}{Colors.RESET}\n")
    
    # Async Orchestrator
    async def run_orchestrator():
        start_time = time.time()
        
        # 3. Live Host Discovery
        current_targets = targets
        if not args.noping and len(current_targets) > 1:
            current_targets = await filter_live_hosts(current_targets)
            if not current_targets:
                print(f"{Colors.RED}[!] No live hosts found. Try --noping to force scan.{Colors.RESET}")
                return

        # 4. Rate Limiter (Created INSIDE the loop)
        rate_limiter = RateLimiter(args.rate) if args.rate > 0 else None

        # 5. Main Scan Loop
        total_hosts = len(current_targets)
        for i, target in enumerate(current_targets, 1):
            print(f"{Colors.BOLD}[*] Scanning {target} ({i}/{total_hosts})...{Colors.RESET}")
            
            try:
                # Direct await, no new asyncio.run
                results = await scan_target(target, ports, args.concurrency, args.timeout, rate_limiter)
                
                print(f"{Colors.GREEN}[+] Completed {target}: {len(results)} open ports{Colors.RESET}")
                
                if results:
                    report_path = generate_report(target, results, args.output)
                    
                    if args.json:
                        from utils.export import export_json
                        export_json({"target": target, "results": results}, args.output)
                        
                    if args.csv:
                        from utils.export import export_csv
                        export_csv({"target": target, "results": results}, args.output)
                        
            except Exception as e:
                print(f"{Colors.RED}[!] Error scanning {target}: {e}{Colors.RESET}")
        
        duration = time.time() - start_time
        print(f"\n{Colors.DIM}{'-'*40}{Colors.RESET}")
        print(f"{Colors.BOLD}Mass Scan Complete!{Colors.RESET}")
        print(f"Total Time: {duration:.2f}s")
        
    # Start the single event loop
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        asyncio.run(run_orchestrator())
        
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(1)

if __name__ == "__main__":
    main()

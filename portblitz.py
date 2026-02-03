
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
    parser.add_argument("target", help="Target IP or Domain")
    parser.add_argument("-c", "--concurrency", type=int, default=500, help="Concurrency level (default: 500)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout (default: 1.0s)")
    parser.add_argument("-p", "--ports", help="Port range (e.g. 1-1000 or 'all')", default="top")
    parser.add_argument("-o", "--output", help="Output directory for reports", default="reports")
    parser.add_argument("--json", action="store_true", help="Export to JSON")
    parser.add_argument("--csv", action="store_true", help="Export to CSV")
    
    args = parser.parse_args()
    
    # Update Version Display
    from utils.display import VERSION
    # Monkey patch version for now or update file (Better to just print it here or update file in next step)
    # We will update utils/display.py separately to v2.0, so just use logic.
    
    print_banner()
    
    target = args.target
    
    # Parse ports
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
        # Single port or comma list
        ports = [int(p) for p in args.ports.split(",")]
        port_desc = f"Specific ({len(ports)} ports)"

    print(f"{Colors.BOLD}Target:{Colors.RESET} {target}")
    print(f"{Colors.BOLD}Ports :{Colors.RESET} {port_desc}")
    print(f"{Colors.BOLD}Speed :{Colors.RESET} {args.concurrency} threads (async)")
    print(f"{Colors.DIM}{'-'*40}{Colors.RESET}\n")
    
    start_time = time.time()
    
    try:
        if sys.platform == 'win32':
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            
        results = asyncio.run(scan_target(target, ports, args.concurrency, args.timeout))
    except KeyboardInterrupt:
        print(f"\n{Colors.YELLOW}[!] Scan interrupted{Colors.RESET}")
        sys.exit(1)
        
    duration = time.time() - start_time
    
    print(f"\n{Colors.DIM}{'-'*40}{Colors.RESET}")
    print(f"{Colors.BOLD}Scan Complete!{Colors.RESET}")
    print(f"Time Taken: {duration:.2f}s")
    print(f"Open Ports: {len(results)}")
    
    if results:
        report_path = generate_report(target, results, args.output)
        print(f"\n{Colors.GREEN}[+] HTML Report saved to: {report_path}{Colors.RESET}")
        
        if args.json:
            from utils.export import export_json
            p = export_json({"target": target, "results": results}, args.output)
            print(f"{Colors.GREEN}[+] JSON Export saved to: {p}{Colors.RESET}")
            
        if args.csv:
            from utils.export import export_csv
            p = export_csv({"target": target, "results": results}, args.output)
            print(f"{Colors.GREEN}[+] CSV Export saved to : {p}{Colors.RESET}")

if __name__ == "__main__":
    main()

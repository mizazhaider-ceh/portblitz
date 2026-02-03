
import time
import asyncio
from typing import List
from utils.display import Colors
from core.live import filter_live_hosts
from core.rate import RateLimiter
from core.scanner import scan_target
from core.engine import ScriptEngine
from utils.cve import lookup_cves
from core.waf import evasion_delay
from modules.bridge import ToolBridge
from utils.report import generate_report

class ScanOrchestrator:
    """
    Manages the scanning process: Live Check -> Rate Limit -> Scan -> Intelligence -> Report.
    Designed to be used by both CLI and TUI.
    """
    def __init__(self, targets: List[str], ports: List[int], options):
        self.targets = targets
        self.ports = ports
        self.options = options # Namespace or dict with args like .rate, .concurrency, etc.
        self.script_engine = ScriptEngine() if getattr(options, 'scripts', False) else None
        
    async def run(self):
        start_time = time.time()
        
        # 1. Live Host Discovery
        current_targets = self.targets
        if not getattr(self.options, 'noping', False) and len(current_targets) > 1:
            current_targets = await filter_live_hosts(current_targets)
            if not current_targets:
                print(f"{Colors.RED}[!] No live hosts found. Try --noping to force scan.{Colors.RESET}")
                return

        # 2. Rate Limiter
        rate_val = getattr(self.options, 'rate', 0)
        rate_limiter = RateLimiter(rate_val) if rate_val > 0 else None
        
        # 3. Main Scan Loop
        total_hosts = len(current_targets)
        all_results = {} # Map target -> open_ports_count for charts (or full results)

        for i, target in enumerate(current_targets, 1):
            print(f"{Colors.BOLD}[*] Scanning {target} ({i}/{total_hosts})...{Colors.RESET}")
            
            try:
                # WAF Evasion
                if getattr(self.options, 'waf', False):
                    await evasion_delay(200, 1000)

                # SCAN
                concurrency = getattr(self.options, 'concurrency', 500)
                timeout = getattr(self.options, 'timeout', 1.0)
                results = await scan_target(target, self.ports, concurrency, timeout, rate_limiter)
                
                print(f"{Colors.GREEN}[+] Completed {target}: {len(results)} open ports{Colors.RESET}")
                
                # Collect stats for return
                if results:
                    all_results[target] = len(results)

                # POST-SCAN INTELLIGENCE
                use_vuln = getattr(self.options, 'vuln', False)
                use_bridge = getattr(self.options, 'bridge', False)
                
                if results and (use_vuln or self.script_engine or use_bridge):
                    print(f"{Colors.CYAN}    Running Intelligence Checks...{Colors.RESET}")
                    
                    for res in results:
                        port = res['port']
                        
                        # 1. CVE Lookup
                        if use_vuln:
                            cves = lookup_cves(str(res))
                            if cves:
                                print(f"    {Colors.RED}[!] CVEs Found for Port {port}: {', '.join(cves)}{Colors.RESET}")
                                res['cves'] = cves
                        
                        # 2. Script Engine
                        if self.script_engine:
                            script_results = await self.script_engine.execute_scripts(target, port, res)
                            if script_results:
                                for sr in script_results:
                                    print(f"    {Colors.MAGENTA}[⚡] {sr['script']}: {sr['output']}{Colors.RESET}")
                                res['scripts'] = script_results
                                
                        # 3. Tool Bridge
                        if use_bridge:
                            # Nmap
                            if port in [21, 22, 80, 443, 445, 3306, 3389]:
                                print(f"    {Colors.YELLOW}[+] Bridging Nmap for Port {port}...{Colors.RESET}")
                                nmap_out = await ToolBridge.run_nmap_version(target, port)
                                res['nmap'] = nmap_out
                                
                            # Nuclei
                            if port in [80, 443, 8080, 8443]:
                                print(f"    {Colors.YELLOW}[+] Bridging Nuclei for Port {port}...{Colors.RESET}")
                                nuclei_out = await ToolBridge.run_nuclei(target, port)
                                if "No results" not in nuclei_out:
                                    res['nuclei'] = nuclei_out

                # EXPORTS
                if results:
                    output_dir = getattr(self.options, 'output', 'reports')
                    generate_report(target, results, output_dir)
                    
                    if getattr(self.options, 'json', False):
                        from utils.export import export_json
                        export_json({"target": target, "results": results}, output_dir)
                    if getattr(self.options, 'csv', False):
                        from utils.export import export_csv
                        export_csv({"target": target, "results": results}, output_dir)
                        
            except Exception as e:
                print(f"{Colors.RED}[!] Error scanning {target}: {e}{Colors.RESET}")
        
        duration = time.time() - start_time
        print(f"\n{Colors.DIM}{'-'*40}{Colors.RESET}")
        print(f"{Colors.BOLD}Mass Scan Complete!{Colors.RESET}")
        print(f"Total Time: {duration:.2f}s")
        
        return all_results

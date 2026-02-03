
import importlib.util
import os
import asyncio
from typing import Dict, List, Any
from pathlib import Path
from utils.display import Colors

class ScriptEngine:
    """
    PortBlitz Script Engine (PBSE).
    Loads and executes python scripts from the 'scripts/' directory.
    """
    def __init__(self, scripts_dir: str = "scripts"):
        self.scripts_dir = scripts_dir
        self.loaded_scripts = {}
        self._load_scripts()

    def _load_scripts(self):
        """Discovers and imports python scripts from the scripts folder."""
        path = Path(self.scripts_dir)
        if not path.exists():
            # Create if it doesn't exist
            path.mkdir(parents=True, exist_ok=True)
            return

        for file_path in path.glob("*.py"):
            if file_path.name == "__init__.py":
                continue
                
            try:
                spec = importlib.util.spec_from_file_location(file_path.stem, file_path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    
                    # Verify it has a run function
                    if hasattr(module, "run") and asyncio.iscoroutinefunction(module.run):
                        self.loaded_scripts[file_path.stem] = module
                        # print(f"DEBUG: Loaded script {file_path.stem}")
            except Exception as e:
                print(f"{Colors.YELLOW}[!] Failed to load script {file_path.name}: {e}{Colors.RESET}")

    async def execute_scripts(self, target: str, port: int, service_info: Dict) -> List[Dict]:
        """
        Run relevant scripts against the target/port.
        Scripts can define a 'TARGET_PORTS' list or 'TARGET_SERVICES' list to filter execution.
        """
        results = []
        
        for name, module in self.loaded_scripts.items():
            run_script = False
            
            # Check Port Match
            if hasattr(module, "TARGET_PORTS"):
                if port in module.TARGET_PORTS:
                    run_script = True
                    
            # Check Service Match (if we have service info)
            if not run_script and hasattr(module, "TARGET_SERVICES") and service_info.get("service"):
                svc_name = service_info.get("service", "").lower()
                if any(s in svc_name for s in module.TARGET_SERVICES):
                    run_script = True
                    
            # Check "ALL" wildcard
            if hasattr(module, "TARGET_PORTS") and "all" in module.TARGET_PORTS:
                run_script = True

            if run_script:
                try:
                    # Timeout enforcement for scripts
                    result = await asyncio.wait_for(module.run(target, port, service_info), timeout=5.0)
                    if result:
                        results.append({
                            "script": name,
                            "output": result
                        })
                except asyncio.TimeoutError:
                    pass # Script took too long
                except Exception as e:
                    # Script error, suppress to keep scanner running
                    pass  
                    
        return results

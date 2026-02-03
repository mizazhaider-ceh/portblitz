
import json
import csv
from pathlib import Path
from typing import List, Dict
from datetime import datetime

def export_json(data: Dict, output_dir: str = "reports") -> str:
    target = data.get("target", "scan")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"{target}_{timestamp}.json"
    path.parent.mkdir(exist_ok=True)
    
    path.write_text(json.dumps(data, indent=2))
    return str(path)

def export_csv(data: Dict, output_dir: str = "reports") -> str:
    target = data.get("target", "scan")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(output_dir) / f"{target}_{timestamp}.csv"
    path.parent.mkdir(exist_ok=True)
    
    results = data.get("results", [])
    if not results:
        return None
        
    keys = ["port", "state", "service", "banner", "http_title", "ssl_info"]
    
    with open(path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=keys)
        writer.writeheader()
        for r in results:
            # Filter dict to only keys we want
            row = {k: r.get(k, "") for k in keys}
            writer.writerow(row)
            
    return str(path)

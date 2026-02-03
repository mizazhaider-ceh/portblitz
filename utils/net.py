
import ipaddress
import socket
from typing import List, Generator
from pathlib import Path

def parse_targets(target_input: str) -> List[str]:
    """
    Parse a single target string which can be:
    - Single IP (192.168.1.1)
    - Domain (example.com)
    - CIDR (192.168.1.0/24)
    - Range (Future)
    """
    targets = []
    
    # Check if CIDR
    if "/" in target_input:
        try:
            net = ipaddress.ip_network(target_input, strict=False)
            # For massive networks, we might want a generator, but for v3.0 list is ok
            # Limit /16 or larger to avoid memory issues if needed
            for ip in net.hosts():
                targets.append(str(ip))
            return targets
        except ValueError:
            pass # Not a valid CIDR, treat as string
            
    # Regular IP/Domain
    targets.append(target_input)
    return targets

def load_targets_from_file(filepath: str) -> List[str]:
    """
    Read targets from a file. Handles comments and empty lines.
    """
    targets = []
    path = Path(filepath)
    if not path.exists():
        raise FileNotFoundError(f"Target file not found: {filepath}")
        
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Sub-parse each line (allows mixing CIDR and IPs in file)
            targets.extend(parse_targets(line))
            
    return list(set(targets)) # Deduplicate

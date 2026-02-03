
import re
from typing import List

# Simple static database of common critical CVEs for demonstration
# In production, this would query an API or a large local DB
CVE_DB = {
    r"Apache/2\.4\.49": ["CVE-2021-41773 (Path Traversal)"],
    r"Apache/2\.4\.50": ["CVE-2021-42013 (RCE)"],
    r"vsFTPd 2\.3\.4": ["CVE-2011-2523 (Backdoor)"],
    r"OpenSSL 1\.0\.1": ["CVE-2014-0160 (Heartbleed)"],
    r"Microsoft-IIS/6\.0": ["CVE-2017-7269 (Buffer Overflow)"],
    r"nginx/1\.18\.0": ["Possible CVE-2021-23017 (Resolve confusion)"],
    r"Exim 4\.92": ["CVE-2019-10149 (RCE)"],
}

def lookup_cves(banner: str) -> List[str]:
    """
    Match banner against known vulnerable versions.
    """
    found_cves = []
    if not banner:
        return found_cves
        
    for pattern, cves in CVE_DB.items():
        if re.search(pattern, banner, re.IGNORECASE):
            found_cves.extend(cves)
            
    return found_cves

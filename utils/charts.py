
from typing import Dict, List
from utils.display import Colors

def print_chart(data: Dict[str, int], title: str = "Scan Statistics"):
    """
    Prints a simple ASCII bar chart.
    data: {'80/tcp': 10, '443/tcp': 5}
    """
    print(f"\n{Colors.BOLD}--- {title} ---{Colors.RESET}")
    
    if not data:
        print("No data to visualize.")
        return

    max_val = max(data.values())
    bar_width = 40
    
    for label, value in data.items():
        # Calculate bar length
        scaled_len = int((value / max_val) * bar_width)
        bar = "█" * scaled_len
        
        # Color based on value intensity
        color = Colors.GREEN
        if value > 10: color = Colors.YELLOW
        if value > 50: color = Colors.RED
        
        print(f"{label:<15} | {color}{bar}{Colors.RESET} ({value})")
    print("")

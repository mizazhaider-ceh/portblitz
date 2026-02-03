
import random
import asyncio

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "PortBlitz/4.0 (Security Scanner; +https://github.com/portblitz)"
]

def get_random_ua() -> str:
    return random.choice(USER_AGENTS)

async def evasion_delay(min_ms: int = 100, max_ms: int = 500):
    """
    Sleep for a random interval to evade simplistic rate detectors.
    """
    delay = random.randint(min_ms, max_ms) / 1000.0
    await asyncio.sleep(delay)

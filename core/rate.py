
import asyncio
import time

class RateLimiter:
    """
    Token Bucket Rate Limiter for Asyncio.
    """
    def __init__(self, rate_limit: int):
        """
        rate_limit: Operations per second (0 = unlimited)
        """
        self.rate_limit = rate_limit
        self.tokens = rate_limit
        self.last_check = time.monotonic()
        self.lock = asyncio.Lock()
        
    async def acquire(self):
        if self.rate_limit <= 0:
            return
            
        async with self.lock:
            while self.tokens < 1:
                now = time.monotonic()
                elapsed = now - self.last_check
                # Replenish tokens based on elapsed time
                new_tokens = elapsed * self.rate_limit
                
                if new_tokens >= 1:
                    self.tokens = min(self.rate_limit, self.tokens + new_tokens)
                    self.last_check = now
                else:
                    # Wait for enough time to get at least 1 token
                    wait_time = (1 - self.tokens) / self.rate_limit
                    await asyncio.sleep(wait_time)
            
            self.tokens -= 1

"""
Rate limiting implementation using token bucket algorithm
Prevents overwhelming targets and respects scan profile limits
"""

import asyncio
import time
from typing import Dict, Optional
from collections import defaultdict
import structlog

logger = structlog.get_logger()


class TokenBucket:
    """
    Token bucket implementation for rate limiting
    Allows bursts while maintaining average rate
    """
    
    def __init__(self, rate: float, capacity: Optional[float] = None):
        """
        Args:
            rate: Tokens per second
            capacity: Maximum bucket size (defaults to rate)
        """
        self.rate = rate
        self.capacity = capacity or rate
        self.tokens = self.capacity
        self.last_update = time.time()
        self.lock = asyncio.Lock()
    
    async def consume(self, tokens: float = 1.0) -> bool:
        """
        Consume tokens from bucket
        Blocks until tokens are available
        """
        async with self.lock:
            while True:
                now = time.time()
                elapsed = now - self.last_update
                
                # Add tokens based on elapsed time
                self.tokens = min(
                    self.capacity,
                    self.tokens + elapsed * self.rate
                )
                self.last_update = now
                
                # Check if we have enough tokens
                if self.tokens >= tokens:
                    self.tokens -= tokens
                    return True
                
                # Calculate wait time
                tokens_needed = tokens - self.tokens
                wait_time = tokens_needed / self.rate
                
                # Wait for tokens to refill
                await asyncio.sleep(wait_time)


class RateLimiter:
    """
    Multi-level rate limiter supporting global and per-domain limits
    Integrates with scan profiles for different rate limits
    """
    
    def __init__(
        self,
        global_rate: float = 10.0,
        default_domain_rate: float = 5.0
    ):
        """
        Args:
            global_rate: Global requests per second limit
            default_domain_rate: Default per-domain requests per second
        """
        self.global_bucket = TokenBucket(global_rate)
        self.default_domain_rate = default_domain_rate
        self.domain_buckets: Dict[str, TokenBucket] = {}
        self.tool_buckets: Dict[str, TokenBucket] = {}
        self.logger = logger.bind(component="rate_limiter")
    
    def set_domain_rate(self, domain: str, rate: float):
        """Set custom rate limit for specific domain"""
        self.domain_buckets[domain] = TokenBucket(rate)
        self.logger.info("Domain rate limit set", domain=domain, rate=rate)
    
    def set_tool_rate(self, tool: str, rate: float):
        """Set rate limit for specific tool"""
        self.tool_buckets[tool] = TokenBucket(rate)
        self.logger.info("Tool rate limit set", tool=tool, rate=rate)
    
    async def acquire(
        self,
        domain: Optional[str] = None,
        tool: Optional[str] = None,
        tokens: float = 1.0
    ):
        """
        Acquire permission to make a request
        Blocks until all rate limits allow the request
        
        Args:
            domain: Target domain (if applicable)
            tool: Tool name (if applicable)
            tokens: Number of tokens to consume (default 1.0)
        """
        # Global rate limit always applies
        await self.global_bucket.consume(tokens)
        
        # Domain-specific rate limit
        if domain:
            if domain not in self.domain_buckets:
                self.domain_buckets[domain] = TokenBucket(self.default_domain_rate)
            await self.domain_buckets[domain].consume(tokens)
        
        # Tool-specific rate limit
        if tool and tool in self.tool_buckets:
            await self.tool_buckets[tool].consume(tokens)
    
    async def acquire_batch(
        self,
        count: int,
        domain: Optional[str] = None,
        tool: Optional[str] = None
    ):
        """
        Acquire permission for a batch of requests
        Useful for tools that make multiple requests
        """
        await self.acquire(domain=domain, tool=tool, tokens=float(count))
    
    def get_stats(self) -> Dict:
        """Get current rate limiter statistics"""
        return {
            "global": {
                "rate": self.global_bucket.rate,
                "tokens": self.global_bucket.tokens,
                "capacity": self.global_bucket.capacity
            },
            "domains": {
                domain: {
                    "rate": bucket.rate,
                    "tokens": bucket.tokens
                }
                for domain, bucket in self.domain_buckets.items()
            },
            "tools": {
                tool: {
                    "rate": bucket.rate,
                    "tokens": bucket.tokens
                }
                for tool, bucket in self.tool_buckets.items()
            }
        }


class ScanProfileRateLimiter(RateLimiter):
    """
    Rate limiter configured based on scan profile
    Different profiles have different rate limits
    """
    
    PROFILE_RATES = {
        "passive": {
            "global": 1.0,  # 1 request per second
            "domain": 0.5,  # Very conservative
        },
        "normal": {
            "global": 10.0,  # 10 requests per second
            "domain": 5.0,
        },
        "aggressive": {
            "global": 50.0,  # 50 requests per second
            "domain": 20.0,
        }
    }
    
    def __init__(self, scan_profile: str = "normal"):
        """
        Initialize rate limiter based on scan profile
        
        Args:
            scan_profile: One of 'passive', 'normal', 'aggressive'
        """
        profile = self.PROFILE_RATES.get(scan_profile, self.PROFILE_RATES["normal"])
        super().__init__(
            global_rate=profile["global"],
            default_domain_rate=profile["domain"]
        )
        self.scan_profile = scan_profile
        self.logger.info(
            "Rate limiter initialized",
            profile=scan_profile,
            global_rate=profile["global"],
            domain_rate=profile["domain"]
        )


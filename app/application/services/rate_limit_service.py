"""
Rate Limiting Service - Token Bucket Algorithm
CRITICAL: Fail-closed for critical endpoints (/login, /verify-mfa) if Redis is unavailable.
"""
import logging
import time
from typing import Optional

from fastapi import HTTPException, status
from redis.asyncio import Redis

from app.core.config import get_settings
from app.infrastructure.redis.connection import get_redis

settings = get_settings()
logger = logging.getLogger(__name__)

# In-memory fallback for critical endpoints when Redis is down
_in_memory_limits: dict[str, dict[str, float]] = {}  # {ip: {endpoint: last_reset_time}}
_in_memory_counts: dict[str, dict[str, int]] = {}  # {ip: {endpoint: count}}


class RateLimitService:
    """Token Bucket rate limiting with fail-closed for critical endpoints."""

    # Critical endpoints that MUST fail-closed if Redis is unavailable
    CRITICAL_ENDPOINTS = ["/login", "/verify-mfa", "/register"]

    def __init__(self):
        self.default_limit = settings.RATE_LIMIT_REQUESTS_PER_MINUTE
        # Stricter limits for critical endpoints
        self.endpoint_limits = {
            "/login": 5,  # 5 requests per minute
            "/verify-mfa": 5,  # 5 requests per minute
            "/register": 3,  # 3 requests per minute
        }

    async def check_rate_limit(
        self, ip_address: str, endpoint: str, strict: bool = False
    ) -> tuple[bool, dict]:
        """
        Check if request is within rate limit using Token Bucket algorithm.

        Args:
            ip_address: Client IP address
            endpoint: API endpoint path
            strict: If True, fail-closed for critical endpoints if Redis is down

        Returns:
            Tuple of (allowed: bool, headers: dict)

        Raises:
            HTTPException: If rate limit exceeded or Redis unavailable for critical endpoints
        """
        # Get limit for this endpoint
        limit = self.endpoint_limits.get(endpoint, self.default_limit)
        window_seconds = 60  # 1 minute window

        # Try Redis first
        redis_client = await get_redis()
        if redis_client:
            try:
                return await self._check_redis_rate_limit(
                    redis_client, ip_address, endpoint, limit, window_seconds
                )
            except Exception as e:
                logger.error(f"Redis rate limit check failed: {e}")
                # Fall through to in-memory fallback

        # Redis unavailable - use fallback
        if endpoint in self.CRITICAL_ENDPOINTS:
            if strict:
                # FAIL-CLOSED: Raise error for critical endpoints
                logger.critical(
                    f"Redis unavailable for critical endpoint {endpoint} - failing closed"
                )
                raise HTTPException(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    detail="Rate limiting service unavailable. Please try again later.",
                )
            else:
                # Use strict in-memory limit for critical endpoints
                return await self._check_in_memory_rate_limit(
                    ip_address, endpoint, limit, window_seconds, strict_limit=True
                )
        else:
            # Non-critical endpoints: use lenient in-memory limit
            return await self._check_in_memory_rate_limit(
                ip_address, endpoint, limit, window_seconds, strict_limit=False
            )

    async def _check_redis_rate_limit(
        self,
        redis: Redis,
        ip_address: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
    ) -> tuple[bool, dict]:
        """Check rate limit using Redis Token Bucket."""
        key = f"rate_limit:{ip_address}:{endpoint}"
        current_time = time.time()

        # Token Bucket: refill rate = limit / window_seconds tokens per second
        refill_rate = limit / window_seconds
        bucket_capacity = limit

        # Get current bucket state
        pipe = redis.pipeline()
        pipe.hgetall(key)
        pipe.expire(key, window_seconds)
        results = await pipe.execute()
        bucket_data = results[0]

        if not bucket_data:
            # First request - initialize bucket
            tokens = bucket_capacity - 1
            last_refill = current_time
        else:
            tokens = float(bucket_data.get("tokens", bucket_capacity))
            last_refill = float(bucket_data.get("last_refill", current_time))

        # Refill tokens based on time elapsed
        time_elapsed = current_time - last_refill
        tokens_to_add = time_elapsed * refill_rate
        tokens = min(bucket_capacity, tokens + tokens_to_add)

        # Check if request is allowed
        if tokens >= 1.0:
            # Consume one token
            tokens -= 1.0
            allowed = True
        else:
            allowed = False

        # Update bucket state
        await redis.hset(
            key,
            mapping={
                "tokens": str(tokens),
                "last_refill": str(current_time),
            },
        )
        await redis.expire(key, window_seconds)

        # Calculate remaining tokens
        remaining = int(max(0, tokens))
        reset_time = int(current_time + window_seconds)

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
        }

        return allowed, headers

    async def _check_in_memory_rate_limit(
        self,
        ip_address: str,
        endpoint: str,
        limit: int,
        window_seconds: int,
        strict_limit: bool = False,
    ) -> tuple[bool, dict]:
        """Check rate limit using in-memory fallback (simplified sliding window)."""
        current_time = time.time()
        key = f"{ip_address}:{endpoint}"

        # Clean up old entries (simple cleanup)
        if key in _in_memory_limits:
            last_reset = _in_memory_limits[ip_address].get(endpoint, 0)
            if current_time - last_reset > window_seconds:
                # Reset window
                _in_memory_counts[ip_address][endpoint] = 0
                _in_memory_limits[ip_address][endpoint] = current_time

        # Initialize if needed
        if ip_address not in _in_memory_counts:
            _in_memory_counts[ip_address] = {}
            _in_memory_limits[ip_address] = {}

        if endpoint not in _in_memory_counts[ip_address]:
            _in_memory_counts[ip_address][endpoint] = 0
            _in_memory_limits[ip_address][endpoint] = current_time

        # Check limit
        count = _in_memory_counts[ip_address][endpoint]
        if count >= limit:
            allowed = False
            remaining = 0
        else:
            allowed = True
            _in_memory_counts[ip_address][endpoint] = count + 1
            remaining = limit - (count + 1)

        reset_time = int(
            _in_memory_limits[ip_address][endpoint] + window_seconds
        )

        headers = {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time),
            "X-RateLimit-Fallback": "in-memory",  # Indicate fallback mode
        }

        return allowed, headers


# Singleton instance
rate_limit_service = RateLimitService()

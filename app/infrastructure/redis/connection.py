"""
Redis Connection Management
Used for rate limiting with Token Bucket algorithm.
"""
import logging
from typing import Optional

import redis.asyncio as aioredis
from redis.asyncio import Redis

from app.core.config import get_settings

settings = get_settings()
logger = logging.getLogger(__name__)

# Global Redis connection pool
_redis_client: Optional[Redis] = None


async def get_redis() -> Optional[Redis]:
    """
    Get Redis client instance.
    Returns None if Redis is unavailable (for graceful degradation).
    """
    global _redis_client
    
    if _redis_client is None:
        try:
            _redis_client = aioredis.from_url(
                settings.REDIS_URL,
                encoding="utf-8",
                decode_responses=True,
                socket_connect_timeout=2,  # Fast timeout for fail-fast
                socket_timeout=2,
                retry_on_timeout=False,
                health_check_interval=30,
            )
            # Test connection
            await _redis_client.ping()
            logger.info("Redis connection established")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {e}")
            _redis_client = None
    
    return _redis_client


async def close_redis() -> None:
    """
    Close Redis connection (called on application shutdown).
    """
    global _redis_client
    if _redis_client:
        await _redis_client.aclose()
        _redis_client = None
        logger.info("Redis connection closed")


async def check_redis_health() -> bool:
    """
    Check if Redis is available and healthy.
    Returns True if Redis is operational, False otherwise.
    """
    try:
        client = await get_redis()
        if client is None:
            return False
        await client.ping()
        return True
    except Exception as e:
        logger.warning(f"Redis health check failed: {e}")
        return False

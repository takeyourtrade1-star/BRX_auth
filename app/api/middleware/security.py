"""
Security Middleware
Extracts client IP from X-Forwarded-For header (for AWS/load balancer environments).
"""
import logging
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)


def extract_client_ip(request: Request) -> str:
    """
    Extract client IP address from request.
    Handles X-Forwarded-For header for AWS/load balancer environments.

    Args:
        request: FastAPI request object

    Returns:
        Client IP address string
    """
    # Check X-Forwarded-For header first (for AWS/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        # X-Forwarded-For can contain multiple IPs: "client, proxy1, proxy2"
        # Take the first one (original client IP)
        client_ip = forwarded_for.split(",")[0].strip()
        if client_ip:
            return client_ip

    # Fallback to X-Real-IP (some proxies use this)
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Last resort: use direct client IP
    if request.client and request.client.host:
        return request.client.host

    # Default fallback
    return "unknown"


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to responses."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Add security headers."""
        response = await call_next(request)

        # Security headers
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = (
            "max-age=31536000; includeSubDomains"
        )

        return response


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Add request context (IP, User-Agent) to request state."""

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        """Extract and store request context."""
        # Extract client IP (handles X-Forwarded-For)
        client_ip = extract_client_ip(request)
        user_agent = request.headers.get("User-Agent")

        # Store in request state for use in routes
        request.state.client_ip = client_ip
        request.state.user_agent = user_agent

        response = await call_next(request)
        return response

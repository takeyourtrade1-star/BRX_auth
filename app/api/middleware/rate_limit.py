import logging
from typing import Callable

from fastapi import Request, status
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.api.middleware.security import extract_client_ip
from app.application.services.rate_limit_service import rate_limit_service

logger = logging.getLogger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    STRICT_ENDPOINTS = ["/api/auth/login", "/api/auth/verify-mfa", "/api/auth/register"]

    async def dispatch(
        self, request: Request, call_next: Callable
    ) -> Response:
        if request.url.path.startswith("/health"):
            return await call_next(request)

        client_ip = extract_client_ip(request)
        endpoint = request.url.path

        strict = endpoint in self.STRICT_ENDPOINTS

        try:
            allowed, headers = await rate_limit_service.check_rate_limit(
                client_ip, endpoint, strict=strict
            )

            if not allowed:
                logger.warning(
                    f"Rate limit exceeded for IP {client_ip} on {endpoint}"
                )
                return JSONResponse(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    content={
                        "detail": "Rate limit exceeded. Please try again later.",
                        "retry_after": headers.get("X-RateLimit-Reset", 60),
                    },
                    headers=headers,
                )

            response = await call_next(request)

            for key, value in headers.items():
                response.headers[key] = str(value)

            return response

        except Exception as e:
            if strict:
                logger.critical(
                    f"Rate limit service failure for critical endpoint {endpoint}: {e}"
                )
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "detail": "Rate limiting service unavailable. Please try again later."
                    },
                )
            else:
                logger.error(f"Rate limit check failed (non-critical): {e}")
                return await call_next(request)

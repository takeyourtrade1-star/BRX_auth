"""
Health Check Routes
Health, readiness, and liveness endpoints.
"""
from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.connection import engine
from app.infrastructure.redis.connection import check_redis_health

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> JSONResponse:
    """Basic health check."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "healthy", "service": "auth-service"},
    )


@router.get("/health/live")
async def liveness_check() -> JSONResponse:
    """Liveness check - service is running."""
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "alive"},
    )


@router.get("/health/ready")
async def readiness_check() -> JSONResponse:
    """Readiness check - service is ready to accept requests (DB + Redis)."""
    checks = {
        "database": False,
        "redis": False,
    }

    # Check database
    try:
        from sqlalchemy import text
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        pass

    # Check Redis
    checks["redis"] = await check_redis_health()

    if all(checks.values()):
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready", "checks": checks},
        )
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not_ready", "checks": checks},
        )

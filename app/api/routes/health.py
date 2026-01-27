from fastapi import APIRouter, status
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.infrastructure.database.connection import engine
from app.infrastructure.redis.connection import check_redis_health

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "healthy", "service": "auth-service"},
    )


@router.get("/health/live")
async def liveness_check() -> JSONResponse:
    return JSONResponse(
        status_code=status.HTTP_200_OK,
        content={"status": "alive"},
    )


@router.get("/health/ready")
async def readiness_check() -> JSONResponse:
    checks = {
        "database": False,
        "redis": False,
    }

    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        checks["database"] = True
    except Exception as e:
        pass

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

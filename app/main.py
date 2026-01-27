import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware

from app.api.exceptions import (
    account_locked_error_handler,
    authentication_error_handler,
    authorization_error_handler,
    generic_exception_handler,
    mfa_verification_error_handler,
    not_found_error_handler,
    request_validation_error_handler,
    validation_error_handler,
)
from app.api.middleware.rate_limit import RateLimitMiddleware
from app.api.middleware.security import (
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.api.routes import auth, health
from app.core.config import get_settings
from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    AuthorizationError,
    MFAVerificationError,
    NotFoundError,
    ValidationError,
)
from app.infrastructure.database.connection import close_db, init_db
from app.infrastructure.redis.connection import close_redis

settings = get_settings()
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting auth service...")
    try:
        await init_db()
        logger.info("Database initialized")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")

    yield

    logger.info("Shutting down auth service...")
    await close_db()
    await close_redis()
    logger.info("Shutdown complete")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Enterprise-grade Authentication Microservice",
    lifespan=lifespan,
    docs_url="/docs" if settings.DEBUG else None,
    redoc_url="/redoc" if settings.DEBUG else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if settings.DEBUG else [],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

if settings.RATE_LIMIT_ENABLED:
    app.add_middleware(RateLimitMiddleware)

app.include_router(health.router)
app.include_router(auth.router)

app.add_exception_handler(AuthenticationError, authentication_error_handler)
app.add_exception_handler(AuthorizationError, authorization_error_handler)
app.add_exception_handler(ValidationError, validation_error_handler)
app.add_exception_handler(NotFoundError, not_found_error_handler)
app.add_exception_handler(AccountLockedError, account_locked_error_handler)
app.add_exception_handler(
    MFAVerificationError, mfa_verification_error_handler
)
app.add_exception_handler(
    RequestValidationError, request_validation_error_handler
)
app.add_exception_handler(Exception, generic_exception_handler)


@app.get("/")
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "running",
    }

"""
Database Connection Management
Async SQLAlchemy 2.0 with conservative pool settings for t3.micro (1GB RAM).
"""
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import QueuePool

from app.core.config import get_settings
from app.infrastructure.database.models import Base

settings = get_settings()

# Conservative pool settings for AWS t3.micro (1GB RAM)
# pool_size=10, max_overflow=5 = max 15 connections
# Note: poolclass is not needed with async engine - SQLAlchemy handles it automatically
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,  # Conservative for t3.micro
    max_overflow=5,  # Conservative for t3.micro
    pool_pre_ping=True,  # Verify connections before using
    pool_recycle=3600,  # Recycle connections after 1 hour
    echo=settings.DEBUG,  # Log SQL queries in debug mode
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """
    Dependency for FastAPI to get database session.
    Yields a database session and ensures proper cleanup.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


@asynccontextmanager
async def get_db_session_context() -> AsyncGenerator[AsyncSession, None]:
    """
    Context manager for database sessions (for use cases).
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """
    Initialize database (create tables if they don't exist).
    Note: In production, use Alembic migrations instead.
    """
    async with engine.begin() as conn:
        # Only create tables if they don't exist
        # In production, this should be handled by Alembic
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    """
    Close database connections (called on application shutdown).
    """
    await engine.dispose()

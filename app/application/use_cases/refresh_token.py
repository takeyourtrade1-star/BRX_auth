"""
Refresh Token Use Case
Refresh access token using refresh token.
"""
import uuid6
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import jwt_manager
from app.domain.schemas.auth import RefreshTokenRequest, TokenResponse
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import (
    AuditLogRepository,
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service


async def refresh_access_token(
    session: AsyncSession,
    request: RefreshTokenRequest,
    ip_address: str,
    user_agent: Optional[str] = None,
) -> TokenResponse:
    """
    Refresh access token using refresh token.

    Args:
        session: Database session
        request: Refresh token request
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        New token response

    Raises:
        AuthenticationError: If token is invalid or expired
    """
    try:
        # Decode refresh token
        payload = jwt_manager.decode_token(request.refresh_token)
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid refresh token")

    # Verify token type
    if payload.get("type") != "refresh":
        raise AuthenticationError("Invalid token type")

    # Get user
    user_id = UUID(payload["sub"])
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    # Verify security stamp matches
    token_security_stamp = UUID(payload["security_stamp"])
    if user.security_stamp != token_security_stamp:
        # Security stamp changed - token invalidated
        raise AuthenticationError("Token has been invalidated")

    # Find session by refresh token hash
    refresh_token_hash = jwt_manager.hash_refresh_token(request.refresh_token)
    session_repo = SessionRepository(session)
    db_session = await session_repo.get_by_token_hash(refresh_token_hash)

    if not db_session:
        raise AuthenticationError("Session not found")

    # Check if session is revoked or expired
    if db_session.is_revoked:
        raise AuthenticationError("Session has been revoked")

    if db_session.expires_at < datetime.now(timezone.utc):
        raise AuthenticationError("Session has expired")

    # Generate new tokens with same security stamp
    access_token = jwt_manager.create_access_token(
        user_id=str(user.id),
        email=user.email,
        security_stamp=str(user.security_stamp),
        mfa_verified=True,  # Refresh tokens only issued after MFA (if enabled)
    )
    new_refresh_token = jwt_manager.create_refresh_token(
        user_id=str(user.id), security_stamp=str(user.security_stamp)
    )

    # Update session with new refresh token hash
    new_refresh_token_hash = jwt_manager.hash_refresh_token(new_refresh_token)
    # Note: In a real implementation, you might want to revoke old session and create new one
    # For simplicity, we'll just update the hash
    from sqlalchemy import update
    from app.infrastructure.database.models import Session
    await session.execute(
        update(Session)
        .where(Session.id == db_session.id)
        .values(refresh_token_hash=new_refresh_token_hash)
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        token_type="bearer",
    )

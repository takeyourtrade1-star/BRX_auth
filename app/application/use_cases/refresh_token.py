from datetime import datetime, timezone
from uuid import UUID

import jwt
from sqlalchemy import update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import jwt_manager
from app.domain.schemas.auth import RefreshTokenRequest, TokenResponse
from app.infrastructure.database.models import Session
from app.infrastructure.database.repositories import (
    SessionRepository,
    UserRepository,
)


async def refresh_access_token(
    session: AsyncSession,
    request: RefreshTokenRequest,
    ip_address: str,
    user_agent: str | None = None,
) -> TokenResponse:
    try:
        payload = jwt_manager.decode_token(request.refresh_token)
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid refresh token")

    if payload.get("type") != "refresh":
        raise AuthenticationError("Invalid token type")

    user_id = UUID(payload["sub"])
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    token_security_stamp = UUID(payload["security_stamp"])
    if user.security_stamp != token_security_stamp:
        raise AuthenticationError("Token has been invalidated")

    refresh_token_hash = jwt_manager.hash_refresh_token(request.refresh_token)
    session_repo = SessionRepository(session)
    db_session = await session_repo.get_by_token_hash(refresh_token_hash)

    if not db_session:
        raise AuthenticationError("Session not found")

    if db_session.is_revoked:
        raise AuthenticationError("Session has been revoked")

    if db_session.expires_at < datetime.now(timezone.utc):
        raise AuthenticationError("Session has expired")

    access_token = jwt_manager.create_access_token(
        user_id=str(user.id),
        email=user.email,
        security_stamp=str(user.security_stamp),
        mfa_verified=True,
    )
    new_refresh_token = jwt_manager.create_refresh_token(
        user_id=str(user.id), security_stamp=str(user.security_stamp)
    )

    new_refresh_token_hash = jwt_manager.hash_refresh_token(new_refresh_token)
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

"""
FastAPI Dependencies
JWT authentication and user extraction.
"""
from typing import Optional
from uuid import UUID

import jwt
from fastapi import Depends, Header, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import jwt_manager
from app.infrastructure.database.connection import get_db_session
from app.infrastructure.database.repositories import UserRepository

security = HTTPBearer()


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    session: AsyncSession = Depends(get_db_session),
) -> "User":
    """
    Get current authenticated user from JWT token.

    Args:
        credentials: HTTP Bearer token credentials
        session: Database session

    Returns:
        User object

    Raises:
        AuthenticationError: If token is invalid or user not found
    """
    token = credentials.credentials

    try:
        # Decode and verify token
        payload = jwt_manager.decode_token(token)
    except jwt.InvalidTokenError:
        raise AuthenticationError("Invalid token")

    # Verify token type
    if payload.get("type") != "access":
        raise AuthenticationError("Invalid token type")

    # Check MFA verified flag
    if not payload.get("mfa_verified", False):
        raise AuthenticationError("MFA verification required")

    # Get user ID
    user_id = UUID(payload["sub"])
    security_stamp = UUID(payload["security_stamp"])

    # Get user from database
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    # Verify security stamp matches (invalidates token if password changed)
    if user.security_stamp != security_stamp:
        raise AuthenticationError("Token has been invalidated")

    return user


async def get_optional_user(
    authorization: Optional[str] = Header(None),
    session: AsyncSession = Depends(get_db_session),
) -> Optional["User"]:
    """
    Get current user if token is provided, otherwise return None.
    Used for endpoints that work with or without authentication.
    """
    if not authorization or not authorization.startswith("Bearer "):
        return None

    token = authorization.replace("Bearer ", "")

    try:
        payload = jwt_manager.decode_token(token)
        if payload.get("type") != "access":
            return None

        user_id = UUID(payload["sub"])
        user_repo = UserRepository(session)
        user = await user_repo.get_by_id(user_id)

        if user and user.security_stamp == UUID(payload["security_stamp"]):
            return user
    except Exception:
        pass

    return None

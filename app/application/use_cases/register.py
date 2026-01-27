"""
Register Use Case
User registration with honeypot validation.
"""
import uuid6
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, ValidationError
from app.core.security import password_hasher
from app.domain.schemas.auth import RegisterRequest, UserResponse
from app.infrastructure.database.models import AccountStatusEnum, EventTypeEnum
from app.infrastructure.database.repositories import AuditLogRepository, UserRepository
from app.application.services.audit_service import audit_service


async def register_user(
    session: AsyncSession,
    request: RegisterRequest,
    ip_address: str,
    user_agent: Optional[str] = None,
) -> UserResponse:
    """
    Register a new user.

    Args:
        session: Database session
        request: Registration request
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        User response

    Raises:
        ValidationError: If honeypot field is filled or email exists
    """
    # HONEYPOT VALIDATION: Silently reject if website_url is filled
    if request.website_url:
        # Log as suspicious activity
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.SUSPICIOUS_ACTIVITY,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "honeypot_triggered", "field": "website_url"},
        )
        # Return generic error (same as invalid credentials)
        raise AuthenticationError("Invalid credentials")

    # Check if email already exists
    user_repo = UserRepository(session)
    existing_user = await user_repo.get_by_email(request.email)
    if existing_user:
        raise ValidationError("Email already registered")

    # Generate UUID v7 for user ID and security stamp
    user_id = uuid6.uuid7()
    security_stamp = uuid6.uuid7()

    # Hash password
    password_hash = password_hasher.hash_password(request.password)

    # Create user
    user = await user_repo.create(
        email=request.email,
        password_hash=password_hash,
        security_stamp=security_stamp,
        account_status=AccountStatusEnum.PENDING_VERIFICATION,
    )

    # Log audit event (async)
    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.LOGIN_SUCCESS,  # Registration is a positive event
        ip_address=ip_address,
        user_id=user.id,
        user_agent=user_agent,
        metadata={"action": "registration"},
    )

    return UserResponse(
        id=user.id,
        email=user.email,
        account_status=user.account_status.value,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
    )

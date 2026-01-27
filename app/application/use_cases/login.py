"""
Login Use Case
User authentication with MFA support and honeypot validation.
"""
import uuid6
from datetime import datetime, timedelta, timezone
from typing import Optional, Union
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AccountLockedError, AuthenticationError, MFARequiredError
from app.core.security import jwt_manager, password_hasher
from app.domain.schemas.auth import LoginRequest, PreAuthTokenResponse, TokenResponse
from app.infrastructure.database.models import AccountStatusEnum, EventTypeEnum
from app.infrastructure.database.repositories import (
    AuditLogRepository,
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service
from app.application.services.device_fingerprint import generate_device_fingerprint


async def login_user(
    session: AsyncSession,
    request: LoginRequest,
    ip_address: str,
    user_agent: Optional[str] = None,
) -> Union[TokenResponse, PreAuthTokenResponse]:
    """
    Authenticate a user.

    Args:
        session: Database session
        request: Login request
        ip_address: Client IP address
        user_agent: User agent string

    Returns:
        TokenResponse if MFA disabled, PreAuthTokenResponse if MFA enabled

    Raises:
        AuthenticationError: If credentials are invalid
        AccountLockedError: If account is locked
        MFARequiredError: If MFA is required (should not happen, handled by return type)
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

    # Get user by email
    user_repo = UserRepository(session)
    user = await user_repo.get_by_email(request.email)

    # Check account lockout
    if user:
        if user.account_status == AccountStatusEnum.LOCKED:
            if user.locked_until and user.locked_until > datetime.now(timezone.utc):
                await audit_service.log_event(
                    session=session,
                    event_type=EventTypeEnum.ACCOUNT_LOCKED,
                    ip_address=ip_address,
                    user_id=user.id,
                    user_agent=user_agent,
                    metadata={"reason": "attempted_login_while_locked"},
                )
                raise AccountLockedError("Account is locked. Please try again later.")

    # Verify password (always check, even if user doesn't exist - prevent timing attacks)
    if not user or not password_hasher.verify_password(
        request.password, user.password_hash
    ):
        # Invalid credentials
        if user:
            # Increment failed attempts
            await user_repo.increment_failed_login_attempts(user.id)
            # Get updated user to check if now locked
            user = await user_repo.get_by_id(user.id)
            if user and user.account_status == AccountStatusEnum.LOCKED:
                await audit_service.log_event(
                    session=session,
                    event_type=EventTypeEnum.ACCOUNT_LOCKED,
                    ip_address=ip_address,
                    user_id=user.id,
                    user_agent=user_agent,
                    metadata={"reason": "max_attempts_reached"},
                )

        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.LOGIN_FAILED,
            ip_address=ip_address,
            user_id=user.id if user else None,
            user_agent=user_agent,
            metadata={"reason": "invalid_password"},
        )
        raise AuthenticationError("Invalid credentials")

    # Check if account is active
    if user.account_status != AccountStatusEnum.ACTIVE:
        if user.account_status == AccountStatusEnum.LOCKED:
            raise AccountLockedError("Account is locked")
        elif user.account_status == AccountStatusEnum.BANNED:
            raise AuthenticationError("Account is banned")
        elif user.account_status == AccountStatusEnum.PENDING_VERIFICATION:
            raise AuthenticationError("Account pending verification")

    # Successful password verification - reset failed attempts
    await user_repo.reset_failed_login_attempts(user.id)

    # Generate new security stamp (invalidates old tokens)
    new_security_stamp = uuid6.uuid7()
    await user_repo.update_security_stamp(user.id, new_security_stamp)

    # Generate device fingerprint
    device_fingerprint = generate_device_fingerprint(user_agent, ip_address)

    # Check if MFA is enabled
    if user.mfa_enabled:
        # Return PRE_AUTH token for MFA verification
        pre_auth_token = jwt_manager.create_pre_auth_token(
            user_id=str(user.id), email=user.email
        )

        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.LOGIN_SUCCESS,
            ip_address=ip_address,
            user_id=user.id,
            user_agent=user_agent,
            metadata={"mfa_required": True},
        )

        return PreAuthTokenResponse(
            pre_auth_token=pre_auth_token, mfa_required=True
        )
    else:
        # MFA not enabled - return full tokens
        access_token = jwt_manager.create_access_token(
            user_id=str(user.id),
            email=user.email,
            security_stamp=str(new_security_stamp),
            mfa_verified=True,
        )
        refresh_token = jwt_manager.create_refresh_token(
            user_id=str(user.id), security_stamp=str(new_security_stamp)
        )

        # Create session
        refresh_token_hash = jwt_manager.hash_refresh_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(
            days=30  # From settings
        )

        session_repo = SessionRepository(session)
        await session_repo.create(
            user_id=user.id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.LOGIN_SUCCESS,
            ip_address=ip_address,
            user_id=user.id,
            user_agent=user_agent,
            metadata={"mfa_required": False},
        )

        return TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
        )

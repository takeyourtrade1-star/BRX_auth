import uuid6
from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AccountLockedError, AuthenticationError
from app.core.security import jwt_manager, password_hasher
from app.domain.schemas.auth import LoginRequest, PreAuthTokenResponse, TokenResponse
from app.infrastructure.database.models import AccountStatusEnum, EventTypeEnum
from app.infrastructure.database.repositories import (
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service
from app.application.services.device_fingerprint import generate_device_fingerprint


async def login_user(
    session: AsyncSession,
    request: LoginRequest,
    ip_address: str,
    user_agent: str | None = None,
) -> TokenResponse | PreAuthTokenResponse:
    if request.website_url:
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.SUSPICIOUS_ACTIVITY,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "honeypot_triggered", "field": "website_url"},
        )
        raise AuthenticationError("Invalid credentials")

    user_repo = UserRepository(session)
    user = await user_repo.get_by_email(request.email)

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

    if not user or not password_hasher.verify_password(
        request.password, user.password_hash
    ):
        if user:
            await user_repo.increment_failed_login_attempts(user.id)
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

    if user.account_status == AccountStatusEnum.LOCKED:
        raise AccountLockedError("Account is locked")
    elif user.account_status == AccountStatusEnum.BANNED:
        raise AuthenticationError("Account is banned")

    await user_repo.reset_failed_login_attempts(user.id)

    new_security_stamp = uuid6.uuid7()
    await user_repo.update_security_stamp(user.id, new_security_stamp)

    device_fingerprint = generate_device_fingerprint(user_agent, ip_address)

    if user.mfa_enabled:
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
        access_token = jwt_manager.create_access_token(
            user_id=str(user.id),
            email=user.email,
            security_stamp=str(new_security_stamp),
            mfa_verified=True,
        )
        refresh_token = jwt_manager.create_refresh_token(
            user_id=str(user.id), security_stamp=str(new_security_stamp)
        )

        refresh_token_hash = jwt_manager.hash_refresh_token(refresh_token)
        expires_at = datetime.now(timezone.utc) + timedelta(days=30)

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

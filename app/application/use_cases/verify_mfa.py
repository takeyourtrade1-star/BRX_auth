from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, MFAVerificationError
from app.core.security import jwt_manager
from app.domain.schemas.auth import TokenResponse, VerifyMFARequest
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import (
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service
from app.application.services.device_fingerprint import generate_device_fingerprint
from app.application.services.mfa_service import mfa_service


async def verify_mfa(
    session: AsyncSession,
    request: VerifyMFARequest,
    ip_address: str,
    user_agent: str | None = None,
) -> TokenResponse:
    try:
        payload = jwt_manager.decode_token(request.pre_auth_token)
    except jwt.InvalidTokenError:
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.MFA_FAILED,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "invalid_pre_auth_token"},
        )
        raise AuthenticationError("Invalid token")

    if payload.get("type") != "pre_auth":
        raise AuthenticationError("Invalid token type")

    user_id = UUID(payload["sub"])
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    if not user.mfa_enabled or not user.mfa_secret_enc:
        raise MFAVerificationError("MFA not enabled for this account")

    try:
        mfa_secret = mfa_service.decrypt_secret(user.mfa_secret_enc)
    except Exception as e:
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.MFA_FAILED,
            ip_address=ip_address,
            user_id=user.id,
            user_agent=user_agent,
            metadata={"reason": "decryption_failed"},
        )
        raise MFAVerificationError("MFA verification failed")

    if not mfa_service.verify_code(mfa_secret, request.mfa_code):
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.MFA_FAILED,
            ip_address=ip_address,
            user_id=user.id,
            user_agent=user_agent,
            metadata={"reason": "invalid_code"},
        )
        raise MFAVerificationError("Invalid MFA code")

    security_stamp = user.security_stamp

    access_token = jwt_manager.create_access_token(
        user_id=str(user.id),
        email=user.email,
        security_stamp=str(security_stamp),
        mfa_verified=True,
    )
    refresh_token = jwt_manager.create_refresh_token(
        user_id=str(user.id), security_stamp=str(security_stamp)
    )

    refresh_token_hash = jwt_manager.hash_refresh_token(refresh_token)
    expires_at = datetime.now(timezone.utc) + timedelta(days=30)

    device_fingerprint = generate_device_fingerprint(user_agent, ip_address)
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
        metadata={"mfa_verified": True},
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type="bearer",
    )

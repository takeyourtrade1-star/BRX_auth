import secrets
import uuid6
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError, ValidationError
from app.core.security import password_hasher
from app.domain.schemas.auth import RegisterRequest, UserPreferenceResponse, UserResponse
from app.infrastructure.database.models import (
    AccountStatusEnum,
    AccountTypeEnum,
    EventTypeEnum,
)
from app.infrastructure.database.repositories import (
    UserConsentRepository,
    UserPreferenceRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service


async def register_user(
    session: AsyncSession,
    request: RegisterRequest,
    ip_address: str,
    user_agent: str | None = None,
) -> UserResponse:
    if request.website_url and request.website_url.strip():
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.SUSPICIOUS_ACTIVITY,
            ip_address=ip_address,
            user_agent=user_agent,
            metadata={"reason": "honeypot_triggered", "field": "website_url"},
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid request",
        )

    user_repo = UserRepository(session)

    existing_user = await user_repo.get_by_username(request.username)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already registered",
        )

    existing_user = await user_repo.get_by_email(request.email)
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    account_type = AccountTypeEnum.PRIVATE if request.account_type == "business" else AccountTypeEnum.PERSONAL

    user_id = uuid6.uuid7()
    security_stamp = uuid6.uuid7()

    password_hash = password_hasher.hash_password(request.password)

    verification_code = secrets.token_urlsafe(8)[:10]
    verification_expires_at = datetime.now(timezone.utc) + timedelta(hours=24)

    user = await user_repo.create(
        username=request.username,
        email=request.email,
        password_hash=password_hash,
        security_stamp=security_stamp,
        account_type=account_type,
        country=request.country,
        phone_prefix=request.phone_prefix,
        phone=request.phone,
        vat_prefix=request.vat_prefix,
        first_name=request.first_name,
        last_name=request.last_name,
        ragione_sociale=request.ragione_sociale,
        piva=request.piva,
        email_verification_code=verification_code,
        email_verification_expires_at=verification_expires_at,
        account_status=AccountStatusEnum.PENDING_VERIFICATION,
    )

    consent_repo = UserConsentRepository(session)
    now = datetime.now(timezone.utc)

    await consent_repo.create(
        user_id=user.id,
        terms_accepted_at=now if request.termsAccepted else None,
        privacy_accepted_at=now if request.privacyAccepted else None,
        cancellation_accepted_at=now if request.cancellationAccepted else None,
        adult_confirmed_at=now if request.adultConfirmed else None,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    pref_repo = UserPreferenceRepository(session)
    await pref_repo.create(
        user_id=user.id,
        theme="system",
        language="it",
        is_onboarding_completed=False,
    )

    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.LOGIN_SUCCESS,
        ip_address=ip_address,
        user_id=user.id,
        user_agent=user_agent,
        metadata={"action": "registration", "account_type": request.account_type},
    )

    preferences_response = UserPreferenceResponse(
        theme="system",
        language="it",
        is_onboarding_completed=False,
        created_at=now,
        updated_at=now,
    )
    return UserResponse(
        id=user.id,
        email=user.email,
        account_status=user.account_status.value,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        preferences=preferences_response,
    )

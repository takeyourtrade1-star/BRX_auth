from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.domain.schemas.auth import MFAQRCodeResponse
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import UserRepository
from app.application.services.audit_service import audit_service
from app.application.services.mfa_service import mfa_service


async def enable_mfa(
    session: AsyncSession,
    user_id: UUID,
    email: str,
) -> MFAQRCodeResponse:
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    secret, qr_code_url, secret_for_manual = mfa_service.generate_setup(email)

    encrypted_secret = mfa_service.encrypt_secret(secret)
    await user_repo.update_mfa(
        user_id=user_id,
        mfa_enabled=False,
        mfa_secret_enc=encrypted_secret,
    )

    return MFAQRCodeResponse(
        qr_code_url=qr_code_url,
        secret=secret_for_manual,
    )


async def verify_and_enable_mfa(
    session: AsyncSession,
    user_id: UUID,
    mfa_code: str,
) -> None:
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    if not user.mfa_secret_enc:
        raise AuthenticationError("MFA secret not found. Please generate setup first.")

    secret = mfa_service.decrypt_secret(user.mfa_secret_enc)

    if not mfa_service.verify_code(secret, mfa_code):
        raise AuthenticationError("Invalid MFA code")

    await user_repo.update_mfa(
        user_id=user_id,
        mfa_enabled=True,
        mfa_secret_enc=user.mfa_secret_enc,
    )

    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.MFA_ENABLED,
        ip_address="system",
        user_id=user_id,
        metadata={"action": "mfa_enabled"},
    )

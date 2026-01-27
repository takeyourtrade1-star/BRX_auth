"""
Enable MFA Use Case
Generate MFA secret and QR code for user setup.
"""
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.domain.schemas.auth import MFAQRCodeResponse
from app.infrastructure.database.repositories import UserRepository
from app.application.services.mfa_service import mfa_service


async def enable_mfa(
    session: AsyncSession,
    user_id: UUID,
    email: str,
) -> MFAQRCodeResponse:
    """
    Generate MFA setup (secret, QR code).

    Args:
        session: Database session
        user_id: User ID
        email: User email

    Returns:
        MFA QR code response

    Raises:
        AuthenticationError: If user not found
    """
    # Get user
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    # Generate MFA setup
    secret, qr_code_url, secret_for_manual = mfa_service.generate_setup(email)

    # Encrypt and store secret (but don't enable yet - user must verify first)
    encrypted_secret = mfa_service.encrypt_secret(secret)
    await user_repo.update_mfa(
        user_id=user_id,
        mfa_enabled=False,  # Not enabled until verified
        mfa_secret_enc=encrypted_secret,
    )

    return MFAQRCodeResponse(
        qr_code_url=qr_code_url,
        secret=secret_for_manual,  # For manual entry in TOTP app
    )


async def verify_and_enable_mfa(
    session: AsyncSession,
    user_id: UUID,
    mfa_code: str,
) -> None:
    """
    Verify MFA code and enable MFA for user.

    Args:
        session: Database session
        user_id: User ID
        mfa_code: TOTP code to verify

    Raises:
        AuthenticationError: If code is invalid or user not found
    """
    from app.infrastructure.database.models import EventTypeEnum
    from app.application.services.audit_service import audit_service

    # Get user
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    if not user.mfa_secret_enc:
        raise AuthenticationError("MFA secret not found. Please generate setup first.")

    # Decrypt secret
    secret = mfa_service.decrypt_secret(user.mfa_secret_enc)

    # Verify code
    if not mfa_service.verify_code(secret, mfa_code):
        raise AuthenticationError("Invalid MFA code")

    # Enable MFA
    await user_repo.update_mfa(
        user_id=user_id,
        mfa_enabled=True,
        mfa_secret_enc=user.mfa_secret_enc,  # Keep existing encrypted secret
    )

    # Log audit event
    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.MFA_ENABLED,
        ip_address="system",  # Internal operation
        user_id=user_id,
        metadata={"action": "mfa_enabled"},
    )

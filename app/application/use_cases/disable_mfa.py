import uuid6
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import password_hasher
from app.domain.schemas.auth import DisableMFARequest
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import UserRepository
from app.application.services.audit_service import audit_service


async def disable_mfa(
    session: AsyncSession,
    user_id: UUID,
    request: DisableMFARequest,
    ip_address: str,
    user_agent: str = None,
) -> None:
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    if not password_hasher.verify_password(request.password, user.password_hash):
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.MFA_FAILED,
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent,
            metadata={"reason": "wrong_password_disable_mfa"},
        )
        raise AuthenticationError("Password is incorrect")

    await user_repo.update_mfa(
        user_id=user_id,
        mfa_enabled=False,
        mfa_secret_enc=None,
    )

    new_security_stamp = uuid6.uuid7()
    await user_repo.update_security_stamp(user_id, new_security_stamp)

    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.MFA_ENABLED,
        ip_address=ip_address,
        user_id=user_id,
        user_agent=user_agent,
        metadata={"action": "mfa_disabled"},
    )

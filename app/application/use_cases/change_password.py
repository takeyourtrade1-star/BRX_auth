import uuid6
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import password_hasher
from app.domain.schemas.auth import ChangePasswordRequest
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import (
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service


async def change_password(
    session: AsyncSession,
    user_id: UUID,
    request: ChangePasswordRequest,
    ip_address: str,
    user_agent: str = None,
) -> None:
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    if not password_hasher.verify_password(
        request.current_password, user.password_hash
    ):
        await audit_service.log_event(
            session=session,
            event_type=EventTypeEnum.PASSWORD_CHANGE,
            ip_address=ip_address,
            user_id=user_id,
            user_agent=user_agent,
            metadata={"reason": "wrong_current_password"},
        )
        raise AuthenticationError("Current password is incorrect")

    new_password_hash = password_hasher.hash_password(request.new_password)

    new_security_stamp = uuid6.uuid7()

    await user_repo.update_password(user_id, new_password_hash, new_security_stamp)

    session_repo = SessionRepository(session)
    await session_repo.revoke_all_user_sessions(
        user_id, reason="password_changed"
    )

    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.PASSWORD_CHANGE,
        ip_address=ip_address,
        user_id=user_id,
        user_agent=user_agent,
        metadata={"reason": "success"},
    )

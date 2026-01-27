import uuid6
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import jwt_manager
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import (
    SessionRepository,
    UserRepository,
)
from app.application.services.audit_service import audit_service


async def logout_user(
    session: AsyncSession,
    user_id: UUID,
    refresh_token: str,
    ip_address: str,
    user_agent: str | None = None,
) -> None:
    refresh_token_hash = jwt_manager.hash_refresh_token(refresh_token)
    session_repo = SessionRepository(session)
    db_session = await session_repo.get_by_token_hash(refresh_token_hash)

    if not db_session or db_session.user_id != user_id:
        raise AuthenticationError("Invalid session")

    await session_repo.revoke_session(
        db_session.id, reason="user_logout"
    )

    new_security_stamp = uuid6.uuid7()
    user_repo = UserRepository(session)
    await user_repo.update_security_stamp(user_id, new_security_stamp)

    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.LOGOUT,
        ip_address=ip_address,
        user_id=user_id,
        user_agent=user_agent,
        metadata={"session_id": str(db_session.id)},
    )

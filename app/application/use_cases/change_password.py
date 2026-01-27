"""
Change Password Use Case
Update user password and invalidate all sessions.
"""
import uuid6
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthenticationError
from app.core.security import password_hasher
from app.domain.schemas.auth import ChangePasswordRequest
from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import (
    AuditLogRepository,
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
    """
    Change user password.

    Args:
        session: Database session
        user_id: User ID
        request: Password change request
        ip_address: Client IP address
        user_agent: User agent string

    Raises:
        AuthenticationError: If current password is incorrect
    """
    # Get user
    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)

    if not user:
        raise AuthenticationError("User not found")

    # Verify current password
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

    # Hash new password
    new_password_hash = password_hasher.hash_password(request.new_password)

    # Generate new security stamp (invalidates all tokens)
    new_security_stamp = uuid6.uuid7()

    # Update password and security stamp
    await user_repo.update_password(user_id, new_password_hash, new_security_stamp)

    # Revoke all existing sessions
    session_repo = SessionRepository(session)
    await session_repo.revoke_all_user_sessions(
        user_id, reason="password_changed"
    )

    # Log audit event
    await audit_service.log_event(
        session=session,
        event_type=EventTypeEnum.PASSWORD_CHANGE,
        ip_address=ip_address,
        user_id=user_id,
        user_agent=user_agent,
        metadata={"reason": "success"},
    )

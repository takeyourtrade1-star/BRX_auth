"""
Repository Layer - Data Access
All database operations using async SQLAlchemy 2.0.
"""
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import uuid6
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models import (
    AccountStatusEnum,
    EventTypeEnum,
    SecurityAuditLog,
    Session,
    User,
)


class UserRepository:
    """Repository for user operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        email: str,
        password_hash: str,
        security_stamp: UUID,
        account_status: AccountStatusEnum = AccountStatusEnum.PENDING_VERIFICATION,
    ) -> User:
        """Create a new user with UUID v7."""
        user = User(
            id=uuid6.uuid7(),
            email=email,
            password_hash=password_hash,
            security_stamp=security_stamp,
            account_status=account_status,
            failed_login_attempts=0,
            mfa_enabled=False,
        )
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        """Get user by ID."""
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        """Get user by email."""
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def update_security_stamp(self, user_id: UUID, new_stamp: UUID) -> None:
        """Update user security stamp."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(security_stamp=new_stamp, updated_at=datetime.now(timezone.utc))
        )

    async def increment_failed_login_attempts(self, user_id: UUID) -> None:
        """Increment failed login attempts."""
        user = await self.get_by_id(user_id)
        if user:
            new_attempts = user.failed_login_attempts + 1
            lock_until = None
            new_status = user.account_status

            # Lock account if max attempts reached
            if new_attempts >= 5:  # From settings, but hardcoded for now
                lock_until = datetime.now(timezone.utc) + timedelta(
                    minutes=30  # From settings
                )
                new_status = AccountStatusEnum.LOCKED

            await self.session.execute(
                update(User)
                .where(User.id == user_id)
                .values(
                    failed_login_attempts=new_attempts,
                    locked_until=lock_until,
                    account_status=new_status,
                    updated_at=datetime.now(timezone.utc),
                )
            )

    async def reset_failed_login_attempts(self, user_id: UUID) -> None:
        """Reset failed login attempts on successful login."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                failed_login_attempts=0,
                locked_until=None,
                account_status=AccountStatusEnum.ACTIVE,
                updated_at=datetime.now(timezone.utc),
            )
        )

    async def update_password(
        self, user_id: UUID, password_hash: str, new_security_stamp: UUID
    ) -> None:
        """Update user password and security stamp."""
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(
                password_hash=password_hash,
                security_stamp=new_security_stamp,
                updated_at=datetime.now(timezone.utc),
            )
        )

    async def update_mfa(
        self,
        user_id: UUID,
        mfa_enabled: bool,
        mfa_secret_enc: Optional[str] = None,
    ) -> None:
        """Update MFA settings."""
        values = {
            "mfa_enabled": mfa_enabled,
            "updated_at": datetime.now(timezone.utc),
        }
        if mfa_secret_enc is not None:
            values["mfa_secret_enc"] = mfa_secret_enc
        await self.session.execute(update(User).where(User.id == user_id).values(**values))


class SessionRepository:
    """Repository for session operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        user_id: UUID,
        refresh_token_hash: str,
        expires_at: datetime,
        device_fingerprint: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> Session:
        """Create a new session with UUID v7."""
        session = Session(
            id=uuid6.uuid7(),
            user_id=user_id,
            refresh_token_hash=refresh_token_hash,
            expires_at=expires_at,
            device_fingerprint=device_fingerprint,
            ip_address=ip_address,
            user_agent=user_agent,
            is_revoked=False,
        )
        self.session.add(session)
        await self.session.flush()
        return session

    async def get_by_token_hash(
        self, refresh_token_hash: str
    ) -> Optional[Session]:
        """Get session by refresh token hash."""
        result = await self.session.execute(
            select(Session).where(
                Session.refresh_token_hash == refresh_token_hash,
                Session.is_revoked == False,
            )
        )
        return result.scalar_one_or_none()

    async def revoke_session(
        self, session_id: UUID, reason: Optional[str] = None
    ) -> None:
        """Revoke a session."""
        await self.session.execute(
            update(Session)
            .where(Session.id == session_id)
            .values(
                is_revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_reason=reason,
            )
        )

    async def revoke_all_user_sessions(
        self, user_id: UUID, reason: Optional[str] = None
    ) -> None:
        """Revoke all sessions for a user."""
        await self.session.execute(
            update(Session)
            .where(Session.user_id == user_id, Session.is_revoked == False)
            .values(
                is_revoked=True,
                revoked_at=datetime.now(timezone.utc),
                revoked_reason=reason,
            )
        )

    async def delete_expired_sessions(self) -> int:
        """Delete expired sessions (cleanup job)."""
        result = await self.session.execute(
            select(Session).where(
                Session.expires_at < datetime.now(timezone.utc)
            )
        )
        expired = result.scalars().all()
        count = len(expired)
        for session in expired:
            await self.session.delete(session)
        return count


class AuditLogRepository:
    """Repository for audit log operations (append-only)."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        event_type: EventTypeEnum,
        ip_address: str,
        user_id: Optional[UUID] = None,
        risk_score: int = 0,
        user_agent: Optional[str] = None,
        geo_location: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> SecurityAuditLog:
        """Create a new audit log entry with UUID v7."""
        audit_log = SecurityAuditLog(
            id=uuid6.uuid7(),
            user_id=user_id,
            event_type=event_type,
            risk_score=risk_score,
            ip_address=ip_address,
            user_agent=user_agent,
            geo_location=geo_location,
            metadata=metadata,
        )
        self.session.add(audit_log)
        await self.session.flush()
        return audit_log

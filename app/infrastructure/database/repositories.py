from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID

import uuid6
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models import (
    AccountStatusEnum,
    AccountTypeEnum,
    EventTypeEnum,
    SecurityAuditLog,
    Session,
    User,
    UserConsent,
    UserPreference,
)


class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        username: str,
        email: str,
        password_hash: str,
        security_stamp: UUID,
        account_type: AccountTypeEnum,
        country: str,
        phone_prefix: str,
        phone: str,
        vat_prefix: Optional[str] = None,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        ragione_sociale: Optional[str] = None,
        piva: Optional[str] = None,
        email_verification_code: Optional[str] = None,
        email_verification_expires_at: Optional[datetime] = None,
        account_status: AccountStatusEnum = AccountStatusEnum.PENDING_VERIFICATION,
    ) -> User:
        user = User(
            id=uuid6.uuid7(),
            username=username,
            email=email,
            password_hash=password_hash,
            security_stamp=security_stamp,
            account_type=account_type,
            country=country,
            phone_prefix=phone_prefix,
            phone=phone,
            vat_prefix=vat_prefix,
            first_name=first_name,
            last_name=last_name,
            ragione_sociale=ragione_sociale,
            piva=piva,
            email_verification_code=email_verification_code,
            email_verification_expires_at=email_verification_expires_at,
            is_active=True,
            account_status=account_status,
            failed_login_attempts=0,
            mfa_enabled=False,
        )
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_id(self, user_id: UUID) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.email == email)
        )
        return result.scalar_one_or_none()

    async def get_by_username(self, username: str) -> Optional[User]:
        result = await self.session.execute(
            select(User).where(User.username == username)
        )
        return result.scalar_one_or_none()

    async def update_security_stamp(self, user_id: UUID, new_stamp: UUID) -> None:
        await self.session.execute(
            update(User)
            .where(User.id == user_id)
            .values(security_stamp=new_stamp, updated_at=datetime.now(timezone.utc))
        )

    async def increment_failed_login_attempts(self, user_id: UUID) -> None:
        user = await self.get_by_id(user_id)
        if user:
            new_attempts = user.failed_login_attempts + 1
            lock_until = None
            new_status = user.account_status

            if new_attempts >= 5:
                lock_until = datetime.now(timezone.utc) + timedelta(minutes=30)
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
        values = {
            "mfa_enabled": mfa_enabled,
            "updated_at": datetime.now(timezone.utc),
        }
        if mfa_secret_enc is not None:
            values["mfa_secret_enc"] = mfa_secret_enc
        await self.session.execute(update(User).where(User.id == user_id).values(**values))


class UserConsentRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        user_id: UUID,
        terms_accepted_at: Optional[datetime] = None,
        privacy_accepted_at: Optional[datetime] = None,
        cancellation_accepted_at: Optional[datetime] = None,
        adult_confirmed_at: Optional[datetime] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UserConsent:
        consent = UserConsent(
            user_id=user_id,
            terms_accepted_at=terms_accepted_at,
            privacy_accepted_at=privacy_accepted_at,
            cancellation_accepted_at=cancellation_accepted_at,
            adult_confirmed_at=adult_confirmed_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        self.session.add(consent)
        await self.session.flush()
        return consent

    async def get_by_user_id(self, user_id: UUID) -> Optional[UserConsent]:
        result = await self.session.execute(
            select(UserConsent).where(UserConsent.user_id == user_id)
        )
        return result.scalar_one_or_none()


class UserPreferenceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(
        self,
        user_id: UUID,
        theme: str = "system",
        language: str = "it",
        is_onboarding_completed: bool = False,
    ) -> UserPreference:
        pref = UserPreference(
            user_id=user_id,
            theme=theme,
            language=language,
            is_onboarding_completed=is_onboarding_completed,
        )
        self.session.add(pref)
        await self.session.flush()
        return pref

    async def get_by_user_id(self, user_id: UUID) -> Optional[UserPreference]:
        result = await self.session.execute(
            select(UserPreference).where(UserPreference.user_id == user_id)
        )
        return result.scalar_one_or_none()

    async def update_onboarding(
        self,
        user_id: UUID,
        theme: str,
        language: str,
        is_onboarding_completed: bool = True,
    ) -> Optional[UserPreference]:
        pref = await self.get_by_user_id(user_id)
        if not pref:
            return None
        pref.theme = theme
        pref.language = language
        pref.is_onboarding_completed = is_onboarding_completed
        pref.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return pref

    async def update_preferences(
        self,
        user_id: UUID,
        *,
        theme: Optional[str] = None,
        language: Optional[str] = None,
        is_onboarding_completed: Optional[bool] = None,
    ) -> Optional[UserPreference]:
        """Partial update of user preferences; only provided fields are updated."""
        pref = await self.get_by_user_id(user_id)
        if not pref:
            # Se non esistono preferenze, le creiamo al volo
            pref = UserPreference(
                user_id=user_id,
                theme=theme or "system",
                language=language or "it",
                is_onboarding_completed=is_onboarding_completed if is_onboarding_completed is not None else False,
            )
            self.session.add(pref)
        else:
            # Aggiornamento parziale
            if theme is not None:
                pref.theme = theme
            if language is not None:
                pref.language = language
            # --- Assicurati che is_onboarding_completed venga salvato nell'UPDATE ---
            if is_onboarding_completed is not None:
                pref.is_onboarding_completed = is_onboarding_completed
            # -----------------------------------------------------------------------
            pref.updated_at = datetime.now(timezone.utc)
        await self.session.flush()
        return pref


class SessionRepository:
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
        event_metadata: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> SecurityAuditLog:
        final_metadata = event_metadata if event_metadata is not None else metadata
        
        audit_log = SecurityAuditLog(
            id=uuid6.uuid7(),
            user_id=user_id,
            event_type=event_type,
            risk_score=risk_score,
            ip_address=ip_address,
            user_agent=user_agent,
            geo_location=geo_location,
            event_metadata=final_metadata,
        )
        self.session.add(audit_log)
        await self.session.flush()
        return audit_log

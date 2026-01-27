import logging
from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.infrastructure.database.models import EventTypeEnum
from app.infrastructure.database.repositories import AuditLogRepository

logger = logging.getLogger(__name__)


class AuditService:
    RISK_SCORES = {
        EventTypeEnum.LOGIN_SUCCESS: 10,
        EventTypeEnum.LOGIN_FAILED: 50,
        EventTypeEnum.LOGOUT: 5,
        EventTypeEnum.PASSWORD_CHANGE: 20,
        EventTypeEnum.MFA_ENABLED: 15,
        EventTypeEnum.MFA_FAILED: 70,
        EventTypeEnum.SUSPICIOUS_ACTIVITY: 90,
        EventTypeEnum.ACCOUNT_LOCKED: 100,
    }

    @staticmethod
    def calculate_risk_score(event_type: EventTypeEnum, metadata: Optional[dict] = None) -> int:
        base_score = AuditService.RISK_SCORES.get(event_type, 0)

        if metadata:
            if "attempt" in metadata:
                attempt = metadata.get("attempt", 1)
                if attempt > 3:
                    base_score = min(100, base_score + 20)

        return min(100, base_score)

    @staticmethod
    async def log_event(
        session: AsyncSession,
        event_type: EventTypeEnum,
        ip_address: str,
        user_id: Optional[UUID] = None,
        user_agent: Optional[str] = None,
        geo_location: Optional[dict] = None,
        metadata: Optional[dict] = None,
    ) -> None:
        try:
            risk_score = AuditService.calculate_risk_score(event_type, metadata)

            audit_repo = AuditLogRepository(session)
            await audit_repo.create(
                event_type=event_type,
                ip_address=ip_address,
                user_id=user_id,
                risk_score=risk_score,
                user_agent=user_agent,
                geo_location=geo_location,
                event_metadata=metadata,
            )

            logger.info(
                f"Audit log created: {event_type.value} for user {user_id} from {ip_address}"
            )
        except Exception as e:
            logger.error(f"Failed to create audit log: {e}", exc_info=True)


audit_service = AuditService()

from fastapi import APIRouter, Depends

from app.api.dependencies import get_current_user
from app.domain.schemas.auth import OnboardingRequest, UserPreferenceUpdate, UserResponse
from app.infrastructure.database.connection import get_db_session
from app.infrastructure.database.models import User
from app.application.use_cases import onboarding as onboarding_uc
from sqlalchemy.ext.asyncio import AsyncSession

router = APIRouter(prefix="/api/users", tags=["Users"])


@router.post("/onboarding", response_model=UserResponse)
async def onboarding(
    request: OnboardingRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    return await onboarding_uc.complete_onboarding(
        session=db,
        user_id=current_user.id,
        request=request,
    )


@router.patch("/preferences", response_model=UserResponse)
async def update_preferences(
    request: UserPreferenceUpdate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> UserResponse:
    return await onboarding_uc.update_user_preferences(
        session=db,
        user_id=current_user.id,
        request=request,
    )

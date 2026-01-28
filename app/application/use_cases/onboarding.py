from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.schemas.auth import OnboardingRequest, UserPreferenceResponse, UserResponse
from app.infrastructure.database.repositories import UserPreferenceRepository, UserRepository


async def complete_onboarding(
    session: AsyncSession,
    user_id: UUID,
    request: OnboardingRequest,
) -> UserResponse:
    pref_repo = UserPreferenceRepository(session)
    pref = await pref_repo.get_by_user_id(user_id)
    if not pref:
        pref = await pref_repo.create(
            user_id=user_id,
            theme=request.theme,
            language=request.language,
            is_onboarding_completed=True,
        )
    else:
        pref = await pref_repo.update_onboarding(
            user_id=user_id,
            theme=request.theme,
            language=request.language,
            is_onboarding_completed=True,
        )

    user_repo = UserRepository(session)
    user = await user_repo.get_by_id(user_id)
    if not user:
        raise ValueError("User not found")

    preferences_response = UserPreferenceResponse(
        theme=pref.theme,
        language=pref.language,
        is_onboarding_completed=pref.is_onboarding_completed,
        created_at=pref.created_at,
        updated_at=pref.updated_at,
    ) if pref else None

    return UserResponse(
        id=user.id,
        email=user.email,
        account_status=user.account_status.value,
        mfa_enabled=user.mfa_enabled,
        created_at=user.created_at,
        preferences=preferences_response,
    )

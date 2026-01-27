from fastapi import APIRouter, BackgroundTasks, Depends, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_current_user
from app.api.middleware.security import extract_client_ip
from app.core.exceptions import (
    AccountLockedError,
    AuthenticationError,
    MFAVerificationError,
    ValidationError,
)
from app.domain.schemas.auth import (
    ChangePasswordRequest,
    DisableMFARequest,
    EnableMFARequest,
    LoginRequest,
    MessageResponse,
    MFAQRCodeResponse,
    PreAuthTokenResponse,
    RefreshTokenRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
    VerifyMFARequest,
)
from app.infrastructure.database.connection import get_db_session
from app.infrastructure.database.models import User
from app.application.use_cases import (
    change_password as change_password_uc,
    disable_mfa as disable_mfa_uc,
    enable_mfa as enable_mfa_uc,
    login as login_uc,
    logout as logout_uc,
    refresh_token as refresh_token_uc,
    register as register_uc,
    verify_mfa as verify_mfa_uc,
)

router = APIRouter(prefix="/api/auth", tags=["Authentication"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    request: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> UserResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    try:
        return await register_uc.register_user(
            session=db,
            request=request,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except ValidationError as e:
        raise
    except AuthenticationError as e:
        raise AuthenticationError("Invalid credentials")


@router.post("/login", response_model=TokenResponse | PreAuthTokenResponse)
async def login_endpoint(
    request: LoginRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> TokenResponse | PreAuthTokenResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    try:
        return await login_uc.login_user(
            session=db,
            request=request,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except AccountLockedError:
        raise
    except AuthenticationError as e:
        raise AuthenticationError("Invalid credentials")


@router.post("/verify-mfa", response_model=TokenResponse)
async def verify_mfa_endpoint(
    request: VerifyMFARequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> TokenResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    try:
        return await verify_mfa_uc.verify_mfa(
            session=db,
            request=request,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except MFAVerificationError:
        raise
    except AuthenticationError:
        raise


@router.post("/refresh", response_model=TokenResponse)
async def refresh_endpoint(
    request: RefreshTokenRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> TokenResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    return await refresh_token_uc.refresh_access_token(
        session=db,
        request=request,
        ip_address=ip_address,
        user_agent=user_agent,
    )


@router.post("/logout", response_model=MessageResponse)
async def logout_endpoint(
    request: RefreshTokenRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> MessageResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    await logout_uc.logout_user(
        session=db,
        user_id=current_user.id,
        refresh_token=request.refresh_token,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return MessageResponse(message="Logged out successfully")


@router.post("/change-password", response_model=MessageResponse)
async def change_password_endpoint(
    request: ChangePasswordRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> MessageResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    await change_password_uc.change_password(
        session=db,
        user_id=current_user.id,
        request=request,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return MessageResponse(message="Password changed successfully")


@router.post("/mfa/enable", response_model=MFAQRCodeResponse)
async def enable_mfa_endpoint(
    request: EnableMFARequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MFAQRCodeResponse:
    return await enable_mfa_uc.enable_mfa(
        session=db,
        user_id=current_user.id,
        email=current_user.email,
    )


@router.post("/mfa/verify", response_model=MessageResponse)
async def verify_mfa_setup_endpoint(
    mfa_code: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
) -> MessageResponse:
    await enable_mfa_uc.verify_and_enable_mfa(
        session=db,
        user_id=current_user.id,
        mfa_code=mfa_code,
    )
    return MessageResponse(message="MFA enabled successfully")


@router.post("/mfa/disable", response_model=MessageResponse)
async def disable_mfa_endpoint(
    request: DisableMFARequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_session),
    http_request: Request = None,
) -> MessageResponse:
    ip_address = extract_client_ip(http_request)
    user_agent = http_request.headers.get("User-Agent")

    await disable_mfa_uc.disable_mfa(
        session=db,
        user_id=current_user.id,
        request=request,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    return MessageResponse(message="MFA disabled successfully")


@router.get("/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: User = Depends(get_current_user),
) -> UserResponse:
    return UserResponse(
        id=current_user.id,
        email=current_user.email,
        account_status=current_user.account_status.value,
        mfa_enabled=current_user.mfa_enabled,
        created_at=current_user.created_at,
    )

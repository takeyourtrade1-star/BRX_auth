from datetime import datetime
from typing import Optional
from uuid import UUID
import re

from pydantic import BaseModel, EmailStr, Field, field_validator, model_validator


class RegisterRequest(BaseModel):
    website_url: str = Field(
        default="",
        description="Honeypot field - MUST be empty string. If filled, request is rejected.",
    )

    username: str = Field(..., min_length=3, max_length=20, description="Username")
    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (min 8 characters, 1 upper, 1 lower, 1 number)",
    )
    account_type: str = Field(..., description="Account type: 'personal' or 'business'")

    country: str = Field(..., min_length=2, max_length=2, description="ISO country code (2 chars)")
    phone_prefix: str = Field(..., max_length=5, description="Phone prefix")
    phone: str = Field(..., max_length=20, description="Phone number")
    vat_prefix: Optional[str] = Field(None, max_length=2, description="VAT prefix (for business)")

    first_name: Optional[str] = Field(None, max_length=100, description="First name (required for personal)")
    last_name: Optional[str] = Field(None, max_length=100, description="Last name (required for personal)")
    ragione_sociale: Optional[str] = Field(None, max_length=255, description="Company name (required for business)")
    piva: Optional[str] = Field(None, max_length=20, description="VAT ID (required for business)")

    termsAccepted: bool = Field(..., description="Terms and conditions acceptance")
    privacyAccepted: bool = Field(..., description="Privacy policy acceptance")
    cancellationAccepted: bool = Field(..., description="Cancellation policy acceptance")
    adultConfirmed: bool = Field(..., description="Adult confirmation")

    @field_validator("website_url")
    @classmethod
    def validate_honeypot(cls, v: str) -> str:
        if v and v.strip():
            raise ValueError("Invalid request")
        return ""

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", v):
            raise ValueError("Username must be 3-20 characters, alphanumeric and underscore only")
        return v

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        return v

    @field_validator("account_type")
    @classmethod
    def validate_account_type(cls, v: str) -> str:
        if v not in ["personal", "business"]:
            raise ValueError("account_type must be 'personal' or 'business'")
        return v

    @model_validator(mode="after")
    def validate_conditional_fields(self):
        account_type = self.account_type

        if account_type == "personal":
            if not self.first_name:
                raise ValueError("first_name is required for personal accounts")
            if not self.last_name:
                raise ValueError("last_name is required for personal accounts")
        elif account_type == "business":
            if not self.ragione_sociale:
                raise ValueError("ragione_sociale is required for business accounts")
            if not self.piva:
                raise ValueError("piva is required for business accounts")

        return self

    class Config:
        json_schema_extra = {
            "example": {
                "website_url": "",
                "username": "johndoe",
                "email": "user@example.com",
                "password": "SecurePass123",
                "account_type": "personal",
                "country": "IT",
                "phone_prefix": "+39",
                "phone": "1234567890",
                "first_name": "John",
                "last_name": "Doe",
                "termsAccepted": True,
                "privacyAccepted": True,
                "cancellationAccepted": True,
                "adultConfirmed": True,
            }
        }


class LoginRequest(BaseModel):
    """
    User login request.
    Contains hidden honeypot field 'website_url' to detect bots.
    If this field is filled, the request should be silently rejected.
    """

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(..., description="User password")
    # HONEYPOT FIELD - Hidden from UI, bots will fill it
    website_url: Optional[str] = Field(
        default=None,
        description="Honeypot field - should always be empty. If filled, request is rejected.",
    )

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!",
            }
        }


class VerifyMFARequest(BaseModel):
    """MFA verification request (used after PRE_AUTH token)."""

    pre_auth_token: str = Field(..., description="PRE_AUTH token from login")
    mfa_code: str = Field(
        ..., min_length=6, max_length=6, description="6-digit TOTP code"
    )

    @field_validator("mfa_code")
    @classmethod
    def validate_mfa_code(cls, v: str) -> str:
        """Validate MFA code is numeric."""
        if not v.isdigit():
            raise ValueError("MFA code must be numeric")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "pre_auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "mfa_code": "123456",
            }
        }


class RefreshTokenRequest(BaseModel):
    """Refresh token request."""

    refresh_token: str = Field(..., description="Refresh token")

    class Config:
        json_schema_extra = {
            "example": {
                "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
            }
        }


class ChangePasswordRequest(BaseModel):
    """Password change request."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="New password (min 12 characters)",
    )

    @field_validator("new_password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "current_password": "OldPassword123!",
                "new_password": "NewSecurePassword123!",
            }
        }


class EnableMFARequest(BaseModel):
    """Request to enable MFA (returns QR code secret)."""

    pass  # No input needed, returns QR code


class DisableMFARequest(BaseModel):
    """Request to disable MFA."""

    password: str = Field(..., description="User password for verification")

    class Config:
        json_schema_extra = {
            "example": {
                "password": "SecurePassword123!",
            }
        }


# ==========================================
# RESPONSE SCHEMAS
# ==========================================


class TokenResponse(BaseModel):
    """JWT token response."""

    access_token: str = Field(..., description="JWT access token")
    refresh_token: str = Field(..., description="JWT refresh token")
    token_type: str = Field(default="bearer", description="Token type")

    class Config:
        json_schema_extra = {
            "example": {
                "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "refresh_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "token_type": "bearer",
            }
        }


class PreAuthTokenResponse(BaseModel):
    """PRE_AUTH token response (when MFA is enabled)."""

    pre_auth_token: str = Field(
        ..., description="Temporary token for MFA verification"
    )
    mfa_required: bool = Field(default=True, description="MFA verification required")

    class Config:
        json_schema_extra = {
            "example": {
                "pre_auth_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
                "mfa_required": True,
            }
        }


class UserPreferenceResponse(BaseModel):
    theme: str = Field(..., description="UI theme: light, dark, system")
    language: str = Field(..., description="ISO 2-char language code")
    is_onboarding_completed: bool = Field(
        ..., description="Whether onboarding wizard was completed"
    )
    created_at: datetime = Field(..., description="Preferences creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")

    class Config:
        from_attributes = True


class OnboardingRequest(BaseModel):
    theme: str = Field(..., description="UI theme: light, dark, system")
    language: str = Field(..., min_length=2, max_length=2, description="ISO 2-char language code")

    @field_validator("theme")
    @classmethod
    def validate_theme(cls, v: str) -> str:
        if v not in ("light", "dark", "system"):
            raise ValueError("theme must be one of: light, dark, system")
        return v

    class Config:
        json_schema_extra = {
            "example": {"theme": "system", "language": "it"},
        }


class UserResponse(BaseModel):
    id: UUID = Field(..., description="User UUID")
    email: str = Field(..., description="User email")
    account_status: str = Field(..., description="Account status")
    mfa_enabled: bool = Field(..., description="MFA enabled status")
    created_at: datetime = Field(..., description="Account creation timestamp")
    preferences: Optional[UserPreferenceResponse] = Field(
        None, description="User UI preferences and onboarding status"
    )

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "01234567-89ab-cdef-0123-456789abcdef",
                "email": "user@example.com",
                "account_status": "active",
                "mfa_enabled": True,
                "created_at": "2026-01-27T12:00:00Z",
                "preferences": None,
            }
        }


class MFAQRCodeResponse(BaseModel):
    """MFA QR code setup response."""

    qr_code_url: str = Field(..., description="QR code data URL for TOTP app")
    secret: str = Field(..., description="MFA secret (for manual entry)")

    class Config:
        json_schema_extra = {
            "example": {
                "qr_code_url": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAA...",
                "secret": "JBSWY3DPEHPK3PXP",
            }
        }


class MessageResponse(BaseModel):
    """Generic message response."""

    message: str = Field(..., description="Response message")

    class Config:
        json_schema_extra = {
            "example": {
                "message": "Operation completed successfully",
            }
        }


# ==========================================
# INTERNAL SCHEMAS (for use cases)
# ==========================================


class AuditLogCreate(BaseModel):
    """Schema for creating audit log entries."""

    user_id: Optional[UUID] = Field(None, description="User ID (nullable)")
    event_type: str = Field(..., description="Event type enum value")
    risk_score: int = Field(default=0, ge=0, le=100, description="Risk score 0-100")
    ip_address: str = Field(..., description="IP address")
    user_agent: Optional[str] = Field(None, description="User agent string")
    geo_location: Optional[dict] = Field(None, description="Geo location JSON")
    event_metadata: Optional[dict] = Field(
        None, 
        description="Additional metadata JSON",
        alias="metadata"  # Accetta anche 'metadata' dall'esterno per retrocompatibilità
    )

    class Config:
        populate_by_name = True  # Permette di usare sia 'event_metadata' che 'metadata'
        json_schema_extra = {
            "example": {
                "user_id": "01234567-89ab-cdef-0123-456789abcdef",
                "event_type": "LOGIN_SUCCESS",
                "risk_score": 10,
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "geo_location": {"country": "IT", "city": "Milan"},
                "event_metadata": {"device": "mobile"},
            }
        }

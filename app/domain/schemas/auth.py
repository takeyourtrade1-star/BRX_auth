"""
Pydantic Schemas for Authentication Domain
Includes anti-bot honeypot fields in RegisterRequest and LoginRequest.
"""
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, EmailStr, Field, field_validator


# ==========================================
# REQUEST SCHEMAS (with Honeypot)
# ==========================================


class RegisterRequest(BaseModel):
    """
    User registration request.
    Contains hidden honeypot field 'website_url' to detect bots.
    If this field is filled, the request should be silently rejected.
    """

    email: EmailStr = Field(..., description="User email address")
    password: str = Field(
        ...,
        min_length=12,
        max_length=128,
        description="Password (min 12 characters)",
    )
    # HONEYPOT FIELD - Hidden from UI, bots will fill it
    website_url: Optional[str] = Field(
        default=None,
        description="Honeypot field - should always be empty. If filled, request is rejected.",
    )

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements."""
        if len(v) < 12:
            raise ValueError("Password must be at least 12 characters long")
        # Add more validation as needed (uppercase, lowercase, numbers, special chars)
        return v

    class Config:
        json_schema_extra = {
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!",
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


class UserResponse(BaseModel):
    """User information response."""

    id: UUID = Field(..., description="User UUID")
    email: str = Field(..., description="User email")
    account_status: str = Field(..., description="Account status")
    mfa_enabled: bool = Field(..., description="MFA enabled status")
    created_at: datetime = Field(..., description="Account creation timestamp")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": "01234567-89ab-cdef-0123-456789abcdef",
                "email": "user@example.com",
                "account_status": "active",
                "mfa_enabled": True,
                "created_at": "2026-01-27T12:00:00Z",
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
    metadata: Optional[dict] = Field(None, description="Additional metadata JSON")

    class Config:
        json_schema_extra = {
            "example": {
                "user_id": "01234567-89ab-cdef-0123-456789abcdef",
                "event_type": "LOGIN_SUCCESS",
                "risk_score": 10,
                "ip_address": "192.168.1.1",
                "user_agent": "Mozilla/5.0...",
                "geo_location": {"country": "IT", "city": "Milan"},
                "metadata": {"device": "mobile"},
            }
        }

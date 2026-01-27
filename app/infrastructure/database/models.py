"""
SQLAlchemy 2.0 Async Models
Exact replication of schema.sql database structure.
"""
import enum
from datetime import datetime
from typing import Optional
from uuid import UUID

from sqlalchemy import (
    Boolean,
    Enum,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TIMESTAMP,
    UniqueConstraint,
    func,
)
from sqlalchemy.dialects.postgresql import INET, JSONB, UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    """Base class for all models."""

    pass


# ==========================================
# ENUMS (Matching schema.sql)
# ==========================================


class AccountStatusEnum(str, enum.Enum):
    """Account status enumeration."""

    ACTIVE = "active"
    LOCKED = "locked"
    BANNED = "banned"
    PENDING_VERIFICATION = "pending_verification"


class EventTypeEnum(str, enum.Enum):
    """Security audit log event type enumeration."""

    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILED = "LOGIN_FAILED"
    LOGOUT = "LOGOUT"
    PASSWORD_CHANGE = "PASSWORD_CHANGE"
    MFA_ENABLED = "MFA_enabled"  # Note: matches schema.sql exactly (lowercase 'enabled')
    MFA_FAILED = "MFA_FAILED"
    SUSPICIOUS_ACTIVITY = "SUSPICIOUS_ACTIVITY"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"


# ==========================================
# 1. USERS TABLE
# ==========================================


class User(Base):
    """
    Users table - The core user account entity.
    Matches schema.sql exactly.
    """

    __tablename__ = "users"

    # Primary Key (UUID v7 generated in application layer)
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, index=True
    )

    # Authentication
    email: Mapped[str] = mapped_column(
        String(255), nullable=False, unique=True, index=True
    )
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)

    # Security & MFA
    security_stamp: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), nullable=False
    )  # Changes on login/logout/password change
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    mfa_secret_enc: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True
    )  # Encrypted with Fernet

    # Account Status & Anti-Brute Force
    account_status: Mapped[AccountStatusEnum] = mapped_column(
        Enum(AccountStatusEnum, name="account_status_enum"),
        nullable=False,
        default=AccountStatusEnum.PENDING_VERIFICATION,
    )
    failed_login_attempts: Mapped[int] = mapped_column(
        Integer, default=0, nullable=False
    )
    locked_until: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.current_timestamp(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.current_timestamp(),
        onupdate=func.current_timestamp(),
        nullable=False,
    )

    # Relationships
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["SecurityAuditLog"]] = relationship(
        "SecurityAuditLog", back_populates="user"
    )

    # Indexes (defined in schema.sql)
    __table_args__ = (Index("idx_users_email", "email"),)


# ==========================================
# 2. SESSIONS TABLE
# ==========================================


class Session(Base):
    """
    Sessions table - Device and refresh token management.
    Matches schema.sql exactly.
    """

    __tablename__ = "sessions"

    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, index=True
    )

    # Foreign Key
    user_id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Refresh Token (SHA-256 hash stored)
    refresh_token_hash: Mapped[str] = mapped_column(
        String(64), nullable=False, unique=True, index=True
    )

    # Fingerprinting for Anti-Hijacking
    device_fingerprint: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(
        INET, nullable=True
    )  # PostgreSQL INET type
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Expiration
    expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), nullable=False
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.current_timestamp(),
        nullable=False,
    )

    # Revocation
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    revoked_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    revoked_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="sessions")

    # Indexes (defined in schema.sql)
    __table_args__ = (
        Index("idx_sessions_token_hash", "refresh_token_hash"),
        Index("idx_sessions_user_id", "user_id"),
    )


# ==========================================
# 3. SECURITY AUDIT LOGS TABLE
# ==========================================


class SecurityAuditLog(Base):
    """
    Security Audit Logs table - Append-only audit trail.
    Matches schema.sql exactly.
    """

    __tablename__ = "security_audit_logs"

    # Primary Key
    id: Mapped[UUID] = mapped_column(
        PG_UUID(as_uuid=True), primary_key=True, index=True
    )

    # Foreign Key (nullable - user may not exist)
    user_id: Mapped[Optional[UUID]] = mapped_column(
        PG_UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Event Type
    event_type: Mapped[EventTypeEnum] = mapped_column(
        Enum(EventTypeEnum, name="event_type_enum"), nullable=False
    )

    # Risk Assessment
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Forensic Data
    ip_address: Mapped[str] = mapped_column(INET, nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    geo_location: Mapped[Optional[dict]] = mapped_column(
        JSONB, nullable=True
    )  # { "country": "IT", "city": "Milan" }
    # Rinominiamo l'attributo Python in 'event_metadata' per evitare conflitti con SQLAlchemy.metadata,
    # ma mappiamo la colonna SQL su "metadata" per rispettare lo schema.sql
    event_metadata: Mapped[Optional[dict]] = mapped_column(
        "metadata", JSONB, nullable=True
    )  # { "reason": "wrong_password", "attempt": 3 }

    # Timestamp
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.current_timestamp(),
        nullable=False,
        index=True,
    )

    # Relationships
    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")

    # Indexes (defined in schema.sql)
    __table_args__ = (
        Index("idx_audit_created_at", "created_at"),
        Index("idx_audit_ip_address", "ip_address"),
    )

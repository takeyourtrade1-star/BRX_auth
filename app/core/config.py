"""
Configuration Management with AWS SSM Parameter Store Support
Loads sensitive values (JWT keys, encryption keys) from AWS SSM or environment variables.
"""
import os
from functools import lru_cache
from typing import Optional

import boto3
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings with AWS SSM integration for secrets."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    APP_NAME: str = "auth-service"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = Field(default=False, description="Debug mode")
    ENVIRONMENT: str = Field(default="production", description="Environment name")

    # Database (PostgreSQL 16)
    DATABASE_URL: str = Field(
        ...,
        description="PostgreSQL connection string (asyncpg format)",
        examples=["postgresql+asyncpg://user:pass@host:5432/dbname"],
    )
    DB_POOL_SIZE: int = Field(default=10, description="Database connection pool size")
    DB_MAX_OVERFLOW: int = Field(default=20, description="Max overflow connections")

    # AWS SSM Configuration
    AWS_REGION: str = Field(default="us-east-1", description="AWS region for SSM")
    AWS_SSM_ENABLED: bool = Field(
        default=True, description="Enable AWS SSM Parameter Store"
    )
    AWS_SSM_PREFIX: str = Field(
        default="/prod/ebartex", description="SSM parameter prefix"
    )

    # JWT Configuration (RS256 - Asymmetric Keys)
    JWT_ALGORITHM: str = Field(default="RS256", description="JWT signing algorithm")
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(
        default=15, description="Access token expiration in minutes"
    )
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = Field(
        default=30, description="Refresh token expiration in days"
    )
    # JWT Keys - Loaded from SSM or env
    JWT_PRIVATE_KEY_SSM_PATH: Optional[str] = Field(
        default="/prod/ebartex/jwt_private_key",
        description="SSM path for JWT private key (PEM format)",
    )
    JWT_PUBLIC_KEY_SSM_PATH: Optional[str] = Field(
        default="/prod/ebartex/jwt_public_key",
        description="SSM path for JWT public key (PEM format)",
    )
    JWT_PRIVATE_KEY: Optional[str] = Field(
        default=None, description="JWT private key (PEM format) - fallback to env"
    )
    JWT_PUBLIC_KEY: Optional[str] = Field(
        default=None, description="JWT public key (PEM format) - fallback to env"
    )

    # Encryption (Fernet for MFA secrets)
    FERNET_KEY_SSM_PATH: Optional[str] = Field(
        default="/prod/ebartex/fernet_key",
        description="SSM path for Fernet encryption key (32-byte base64)",
    )
    FERNET_KEY: Optional[str] = Field(
        default=None, description="Fernet key (base64) - fallback to env"
    )

    # Security
    ARGON2_MEMORY_COST: int = Field(
        default=65536, description="Argon2 memory cost (64 MB)"
    )
    ARGON2_TIME_COST: int = Field(default=3, description="Argon2 time cost")
    ARGON2_PARALLELISM: int = Field(default=4, description="Argon2 parallelism")

    # Rate Limiting (Redis)
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for rate limiting",
    )
    RATE_LIMIT_ENABLED: bool = Field(
        default=True, description="Enable rate limiting"
    )
    RATE_LIMIT_REQUESTS_PER_MINUTE: int = Field(
        default=60, description="Default rate limit (requests per minute)"
    )

    # Account Security
    MAX_FAILED_LOGIN_ATTEMPTS: int = Field(
        default=5, description="Max failed login attempts before lockout"
    )
    ACCOUNT_LOCKOUT_DURATION_MINUTES: int = Field(
        default=30, description="Account lockout duration in minutes"
    )

    # MFA
    MFA_ISSUER_NAME: str = Field(
        default="Auth Service", description="MFA TOTP issuer name"
    )

    @field_validator("DATABASE_URL")
    @classmethod
    def validate_database_url(cls, v: str) -> str:
        """Ensure database URL uses asyncpg driver."""
        if not v.startswith("postgresql+asyncpg://"):
            raise ValueError(
                "DATABASE_URL must use asyncpg driver: postgresql+asyncpg://..."
            )
        return v

    def __init__(self, **kwargs):
        """Initialize settings and load secrets from AWS SSM if enabled."""
        super().__init__(**kwargs)
        if self.AWS_SSM_ENABLED:
            self._load_secrets_from_ssm()

    def _load_secrets_from_ssm(self) -> None:
        """Load sensitive values from AWS SSM Parameter Store."""
        try:
            ssm_client = boto3.client("ssm", region_name=self.AWS_REGION)

            # Load JWT keys
            if self.JWT_PRIVATE_KEY_SSM_PATH and not self.JWT_PRIVATE_KEY:
                try:
                    response = ssm_client.get_parameter(
                        Name=self.JWT_PRIVATE_KEY_SSM_PATH, WithDecryption=True
                    )
                    self.JWT_PRIVATE_KEY = response["Parameter"]["Value"]
                except ssm_client.exceptions.ParameterNotFound:
                    pass  # Fallback to env var

            if self.JWT_PUBLIC_KEY_SSM_PATH and not self.JWT_PUBLIC_KEY:
                try:
                    response = ssm_client.get_parameter(
                        Name=self.JWT_PUBLIC_KEY_SSM_PATH, WithDecryption=False
                    )
                    self.JWT_PUBLIC_KEY = response["Parameter"]["Value"]
                except ssm_client.exceptions.ParameterNotFound:
                    pass  # Fallback to env var

            # Load Fernet key
            if self.FERNET_KEY_SSM_PATH and not self.FERNET_KEY:
                try:
                    response = ssm_client.get_parameter(
                        Name=self.FERNET_KEY_SSM_PATH, WithDecryption=True
                    )
                    self.FERNET_KEY = response["Parameter"]["Value"]
                except ssm_client.exceptions.ParameterNotFound:
                    pass  # Fallback to env var

        except Exception as e:
            # If SSM fails, fall back to environment variables
            # This allows local development without AWS credentials
            if self.DEBUG:
                print(f"Warning: Could not load from SSM: {e}. Using environment variables.")

    @property
    def jwt_private_key_bytes(self) -> bytes:
        """Get JWT private key as bytes."""
        if not self.JWT_PRIVATE_KEY:
            raise ValueError("JWT_PRIVATE_KEY not configured")
        return self.JWT_PRIVATE_KEY.encode("utf-8")

    @property
    def jwt_public_key_bytes(self) -> bytes:
        """Get JWT public key as bytes."""
        if not self.JWT_PUBLIC_KEY:
            raise ValueError("JWT_PUBLIC_KEY not configured")
        return self.JWT_PUBLIC_KEY.encode("utf-8")

    @property
    def fernet_key_bytes(self) -> bytes:
        """Get Fernet key as bytes."""
        if not self.FERNET_KEY:
            raise ValueError("FERNET_KEY not configured")
        return self.FERNET_KEY.encode("utf-8")


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance (singleton pattern)."""
    return Settings()

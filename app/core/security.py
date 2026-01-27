"""
Security Utilities: Argon2id, JWT RS256, Fernet Encryption
Enterprise-grade security functions for authentication service.
"""
import hashlib
from datetime import datetime, timedelta, timezone
from typing import Optional

import jwt
from cryptography.fernet import Fernet
from passlib.context import CryptContext
from passlib.hash import argon2

from app.core.config import get_settings

settings = get_settings()

# Argon2id Password Hashing Context
pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__memory_cost=settings.ARGON2_MEMORY_COST,
    argon2__time_cost=settings.ARGON2_TIME_COST,
    argon2__parallelism=settings.ARGON2_PARALLELISM,
    deprecated="auto",
)


class PasswordHasher:
    """Argon2id password hashing utilities."""

    @staticmethod
    def hash_password(password: str) -> str:
        """
        Hash a password using Argon2id.

        Args:
            password: Plain text password

        Returns:
            Hashed password string
        """
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        """
        Verify a password against its hash.

        Args:
            plain_password: Plain text password to verify
            hashed_password: Stored password hash

        Returns:
            True if password matches, False otherwise
        """
        return pwd_context.verify(plain_password, hashed_password)


class JWTManager:
    """JWT token management with RS256 (asymmetric keys)."""

    def __init__(self):
        self.algorithm = settings.JWT_ALGORITHM
        self.private_key = settings.jwt_private_key_bytes
        self.public_key = settings.jwt_public_key_bytes
        self.access_token_expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
        self.refresh_token_expire_days = settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS

    def create_access_token(
        self,
        user_id: str,
        email: str,
        security_stamp: str,
        mfa_verified: bool = True,
    ) -> str:
        """
        Create a JWT access token.

        Args:
            user_id: User UUID
            email: User email
            security_stamp: Current security stamp (invalidates on password change)
            mfa_verified: Whether MFA has been verified (False for PRE_AUTH tokens)

        Returns:
            Encoded JWT token
        """
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=self.access_token_expire_minutes
        )
        payload = {
            "sub": user_id,  # Subject (user ID)
            "email": email,
            "security_stamp": security_stamp,
            "mfa_verified": mfa_verified,
            "type": "access",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def create_pre_auth_token(self, user_id: str, email: str) -> str:
        """
        Create a PRE_AUTH token for MFA verification step.

        Args:
            user_id: User UUID
            email: User email

        Returns:
            Encoded JWT token with mfa_verified=False
        """
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)  # Short-lived
        payload = {
            "sub": user_id,
            "email": email,
            "mfa_verified": False,
            "type": "pre_auth",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def create_refresh_token(self, user_id: str, security_stamp: str) -> str:
        """
        Create a JWT refresh token.

        Args:
            user_id: User UUID
            security_stamp: Current security stamp

        Returns:
            Encoded JWT token
        """
        expire = datetime.now(timezone.utc) + timedelta(
            days=self.refresh_token_expire_days
        )
        payload = {
            "sub": user_id,
            "security_stamp": security_stamp,
            "type": "refresh",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def decode_token(self, token: str) -> dict:
        """
        Decode and verify a JWT token.

        Args:
            token: JWT token string

        Returns:
            Decoded token payload

        Raises:
            jwt.InvalidTokenError: If token is invalid, expired, or tampered
        """
        return jwt.decode(
            token, self.public_key, algorithms=[self.algorithm], options={"verify_exp": True}
        )

    def hash_refresh_token(self, token: str) -> str:
        """
        Hash a refresh token for storage (SHA-256).

        Args:
            token: Plain refresh token

        Returns:
            SHA-256 hash of the token
        """
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


class EncryptionManager:
    """Fernet encryption for sensitive data (MFA secrets)."""

    def __init__(self):
        key_str = settings.FERNET_KEY
        if not key_str:
            raise ValueError("FERNET_KEY not configured")
        
        # Fernet key must be 32 bytes, URL-safe base64-encoded
        # The key from SSM/env should already be in the correct format
        try:
            # Fernet expects a URL-safe base64-encoded 32-byte key
            # If the key is provided as a string, it should already be base64
            self.fernet = Fernet(key_str.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid Fernet key format: {e}")

    def encrypt(self, plaintext: str) -> str:
        """
        Encrypt a string using Fernet.

        Args:
            plaintext: Plain text to encrypt

        Returns:
            Encrypted string (base64-encoded)
        """
        return self.fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """
        Decrypt a Fernet-encrypted string.

        Args:
            ciphertext: Encrypted string

        Returns:
            Decrypted plain text

        Raises:
            cryptography.fernet.InvalidToken: If decryption fails
        """
        return self.fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


# Singleton instances
password_hasher = PasswordHasher()
jwt_manager = JWTManager()
encryption_manager = EncryptionManager()

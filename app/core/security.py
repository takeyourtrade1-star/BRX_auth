import hashlib
from datetime import datetime, timedelta, timezone

import jwt
from cryptography.fernet import Fernet
from passlib.context import CryptContext

from app.core.config import get_settings

settings = get_settings()

pwd_context = CryptContext(
    schemes=["argon2"],
    argon2__memory_cost=settings.ARGON2_MEMORY_COST,
    argon2__time_cost=settings.ARGON2_TIME_COST,
    argon2__parallelism=settings.ARGON2_PARALLELISM,
    deprecated="auto",
)


class PasswordHasher:
    @staticmethod
    def hash_password(password: str) -> str:
        return pwd_context.hash(password)

    @staticmethod
    def verify_password(plain_password: str, hashed_password: str) -> bool:
        return pwd_context.verify(plain_password, hashed_password)


class JWTManager:
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
        expire = datetime.now(timezone.utc) + timedelta(
            minutes=self.access_token_expire_minutes
        )
        payload = {
            "sub": user_id,
            "email": email,
            "security_stamp": security_stamp,
            "mfa_verified": mfa_verified,
            "type": "access",
            "exp": expire,
            "iat": datetime.now(timezone.utc),
        }
        return jwt.encode(payload, self.private_key, algorithm=self.algorithm)

    def create_pre_auth_token(self, user_id: str, email: str) -> str:
        expire = datetime.now(timezone.utc) + timedelta(minutes=5)
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
        return jwt.decode(
            token, self.public_key, algorithms=[self.algorithm], options={"verify_exp": True}
        )

    def hash_refresh_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()


class EncryptionManager:
    def __init__(self):
        key_str = settings.FERNET_KEY
        if not key_str:
            raise ValueError("FERNET_KEY not configured")
        
        try:
            self.fernet = Fernet(key_str.encode("utf-8"))
        except Exception as e:
            raise ValueError(f"Invalid Fernet key format: {e}")

    def encrypt(self, plaintext: str) -> str:
        return self.fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        return self.fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")


password_hasher = PasswordHasher()
jwt_manager = JWTManager()
encryption_manager = EncryptionManager()

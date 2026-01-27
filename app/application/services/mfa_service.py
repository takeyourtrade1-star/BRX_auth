"""
MFA Service - TOTP (Time-based One-Time Password)
Generates and verifies TOTP codes using pyotp.
"""
import base64
import io
from typing import Tuple

import pyotp
import qrcode
from qrcode.image.pil import PilImage

from app.core.config import get_settings
from app.core.security import encryption_manager

settings = get_settings()


class MFAService:
    """MFA service for TOTP generation and verification."""

    @staticmethod
    def generate_secret() -> str:
        """
        Generate a new TOTP secret.

        Returns:
            Base32-encoded secret string
        """
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        """
        Generate TOTP URI for QR code.

        Args:
            secret: TOTP secret (plain text, will be encrypted before storage)
            email: User email for label

        Returns:
            TOTP URI string
        """
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=settings.MFA_ISSUER_NAME,
        )

    @staticmethod
    def generate_qr_code(uri: str) -> str:
        """
        Generate QR code as base64 data URL.

        Args:
            uri: TOTP URI string

        Returns:
            Base64-encoded PNG data URL
        """
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        # Encode as base64 data URL
        img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
        return f"data:image/png;base64,{img_base64}"

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        """
        Verify a TOTP code.

        Args:
            secret: TOTP secret (decrypted)
            code: 6-digit code to verify

        Returns:
            True if code is valid, False otherwise
        """
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)  # Allow 1 time step tolerance

    @staticmethod
    def encrypt_secret(secret: str) -> str:
        """
        Encrypt MFA secret before storage.

        Args:
            secret: Plain TOTP secret

        Returns:
            Encrypted secret string
        """
        return encryption_manager.encrypt(secret)

    @staticmethod
    def decrypt_secret(encrypted_secret: str) -> str:
        """
        Decrypt MFA secret from storage.

        Args:
            encrypted_secret: Encrypted secret string

        Returns:
            Decrypted plain secret
        """
        return encryption_manager.decrypt(encrypted_secret)

    @staticmethod
    def generate_setup(
        email: str,
    ) -> Tuple[str, str, str]:
        """
        Generate complete MFA setup (secret, URI, QR code).

        Args:
            email: User email

        Returns:
            Tuple of (plain_secret, qr_code_url, secret_for_manual_entry)
        """
        # Generate secret
        secret = MFAService.generate_secret()

        # Generate URI
        uri = MFAService.get_totp_uri(secret, email)

        # Generate QR code
        qr_code_url = MFAService.generate_qr_code(uri)

        return secret, qr_code_url, secret


# Singleton instance
mfa_service = MFAService()

import base64
import io
from typing import Tuple

import pyotp
import qrcode

from app.core.config import get_settings
from app.core.security import encryption_manager

settings = get_settings()


class MFAService:
    @staticmethod
    def generate_secret() -> str:
        return pyotp.random_base32()

    @staticmethod
    def get_totp_uri(secret: str, email: str) -> str:
        totp = pyotp.TOTP(secret)
        return totp.provisioning_uri(
            name=email,
            issuer_name=settings.MFA_ISSUER_NAME,
        )

    @staticmethod
    def generate_qr_code(uri: str) -> str:
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format="PNG")
        buffer.seek(0)

        img_base64 = base64.b64encode(buffer.read()).decode("utf-8")
        return f"data:image/png;base64,{img_base64}"

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)

    @staticmethod
    def encrypt_secret(secret: str) -> str:
        return encryption_manager.encrypt(secret)

    @staticmethod
    def decrypt_secret(encrypted_secret: str) -> str:
        return encryption_manager.decrypt(encrypted_secret)

    @staticmethod
    def generate_setup(
        email: str,
    ) -> Tuple[str, str, str]:
        secret = MFAService.generate_secret()
        uri = MFAService.get_totp_uri(secret, email)
        qr_code_url = MFAService.generate_qr_code(uri)
        return secret, qr_code_url, secret


mfa_service = MFAService()

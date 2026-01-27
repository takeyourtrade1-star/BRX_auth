"""
Device Fingerprinting Service
Generates consistent device fingerprints for session tracking and anti-hijacking.
"""
import hashlib
from typing import Optional


def generate_device_fingerprint(
    user_agent: Optional[str], ip_address: Optional[str]
) -> str:
    """
    Generate a device fingerprint from User-Agent and IP address.

    Args:
        user_agent: HTTP User-Agent header
        ip_address: Client IP address

    Returns:
        SHA-256 hash of the fingerprint
    """
    # Normalize inputs
    ua = user_agent or "unknown"
    ip = ip_address or "unknown"

    # Create fingerprint string
    fingerprint_string = f"{ua}|{ip}"

    # Hash for consistency and privacy
    return hashlib.sha256(fingerprint_string.encode("utf-8")).hexdigest()

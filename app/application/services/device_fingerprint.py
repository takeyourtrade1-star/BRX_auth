import hashlib


def generate_device_fingerprint(
    user_agent: str | None, ip_address: str | None
) -> str:
    ua = user_agent or "unknown"
    ip = ip_address or "unknown"
    fingerprint_string = f"{ua}|{ip}"
    return hashlib.sha256(fingerprint_string.encode("utf-8")).hexdigest()

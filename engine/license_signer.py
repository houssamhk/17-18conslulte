"""Offline license signing helpers. Never ship the private signing key."""

import os
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt


def _private_key_path() -> Path:
    configured = os.environ.get("ALG_PII_LICENSE_PRIVATE_KEY")
    if configured:
        return Path(configured).expanduser().resolve()
    local_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    return local_data / "AlgPIIEngineIssuer" / "private_signing_key.pem"


def generate_license(hwid: str, days_valid: int = 365) -> str:
    """Sign a hardware-bound license using the issuer's external RSA key."""
    normalized_hwid = (hwid or "").strip().upper()
    if not normalized_hwid:
        raise ValueError("A client hardware ID is required.")
    if not isinstance(days_valid, int) or not 1 <= days_valid <= 3650:
        raise ValueError("License duration must be between 1 and 3650 days.")

    path = _private_key_path()
    if not path.is_file():
        raise FileNotFoundError(
            "Private signing key was not found. Set ALG_PII_LICENSE_PRIVATE_KEY "
            "to the offline issuer key file."
        )
    private_key = path.read_text(encoding="ascii")
    now = datetime.now(timezone.utc)
    payload = {
        "hwid": normalized_hwid,
        "exp": now + timedelta(days=days_valid),
        "iat": now,
        "product": "Alg-PII Engine Enterprise",
    }
    return jwt.encode(payload, private_key, algorithm="RS256")

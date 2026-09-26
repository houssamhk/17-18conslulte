import uuid
import hashlib
import platform
import jwt
import logging
from typing import Tuple, Optional
import keyring

class LicenseManager:
    """Manages Hardware ID generation and JWT License Validation."""
    
    SECRET_KEY = "ALG_PII_SOVEREIGN_REGTECH_SECRET_KEY_2026"
    SERVICE_NAME = "AlgPIIEngine_License"
    KEY_ACCOUNT = "license_token"

    @staticmethod
    def get_hardware_id() -> str:
        """Generates a unique hardware identifier based on MAC address and system info."""
        mac = str(uuid.getnode())
        system = platform.node() + platform.system()
        raw_id = f"{mac}-{system}"
        return hashlib.sha256(raw_id.encode()).hexdigest()[:16].upper()

    @staticmethod
    def validate_license(token: str) -> Tuple[bool, str]:
        """Validates a JWT license token against the machine's HWID."""
        try:
            hwid = LicenseManager.get_hardware_id()
            decoded = jwt.decode(token, LicenseManager.SECRET_KEY, algorithms=["HS256"])
            
            if decoded.get("hwid") != hwid:
                return False, "رقم الجهاز غير متطابق (Hardware ID mismatch)."
                
            return True, "الرخصة صالحة (License Valid)."
        except jwt.ExpiredSignatureError:
            return False, "انتهت صلاحية الرخصة (License expired)."
        except jwt.InvalidTokenError:
            return False, "مفتاح الرخصة غير صالح (Invalid license token)."
        except Exception as e:
            return False, f"خطأ في التحقق (Validation error): {str(e)}"

    @staticmethod
    def save_license(token: str) -> bool:
        """Saves the valid license token to the OS keychain."""
        try:
            keyring.set_password(LicenseManager.SERVICE_NAME, LicenseManager.KEY_ACCOUNT, token)
            return True
        except Exception as e:
            logging.error(f"Failed to save license: {e}")
            return False

    @staticmethod
    def load_license() -> Optional[str]:
        """Loads the license token from the OS keychain."""
        try:
            return keyring.get_password(LicenseManager.SERVICE_NAME, LicenseManager.KEY_ACCOUNT)
        except Exception as e:
            logging.error(f"Failed to load license: {e}")
            return None

    @staticmethod
    def is_activated() -> bool:
        """Checks if the application is currently activated with a valid license."""
        token = LicenseManager.load_license()
        if not token:
            return False
        is_valid, _ = LicenseManager.validate_license(token)
        return is_valid

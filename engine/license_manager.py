import uuid
import hashlib
import platform
import jwt
import logging
from typing import Tuple, Optional
import keyring

class LicenseManager:
    """Manages Hardware ID generation and JWT License Validation."""
    
    # Public verification key only. The corresponding private signing key is
    # kept by the license issuer and is never included in the desktop build.
    PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAot6Ao7Y3mGP/Kk0yhD6U
3nLath05ZrMsxT8vv3rzJuh5A+cno8TtTsdmW+xqSmxSN6NoJCSm3nxB5+DTftr0
rBQEq4Ibyhe/oqETyPS45+a74TLH+Gv11E+F8kNIV/SQKIPKFGf9nryqbWTzizX0
sqpUvh2P2E41VV6pKpvr7Qfquvn9u9pgKMwa3dtnH8TecpHtxxJEYsf2UoRyFuxh
eFUV/XK2HOR5cTfyd0XHb01XyCL/LRUB2DPj8vAIGw+cur/yyzXslDlbtINpItbQ
e7+nLi5wYEkt7D9ptbYTi/B3HKoUgKGdY9tDFzvONCnAFyIipLy2qjUB23XG0PXq
NZwVB4ZXEVksXi3rYshVa91hykAA9FVO4Z5Sck4UBJnzlQ8HHn3F03yNFiW3s5MO
hyR9QQg1KjtEF82EY9xv11EZDO9PoAwheZpTdxgHOTnjmDBGkJaJPtUSqm90U5nY
muENOdXkTYXSSbxXE9F9r8lqVwSb5t3NswUtXl9mqjehAgMBAAE=
-----END PUBLIC KEY-----"""
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
            decoded = jwt.decode(token, LicenseManager.PUBLIC_KEY, algorithms=["RS256"])
            
            if decoded.get("hwid") != hwid:
                return False, "رقم الجهاز غير متطابق (Hardware ID mismatch)."
            if decoded.get("product") != "Alg-PII Engine Enterprise":
                return False, "الرخصة لا تخص هذا المنتج (License product mismatch)."
                
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

import keyring
import logging
from typing import Optional
from cryptography.fernet import Fernet

class KeyManager:
    """
    Cryptographic Key Management using Windows DPAPI via keyring.
    Never writes keys to disk in plaintext.
    """
    SERVICE_NAME = 'AlgPIIEngine'
    KEY_ACCOUNT = 'master_key'
    AUDIT_HEAD_ACCOUNT = 'audit_log_head'

    @staticmethod
    def generate_key() -> bytes:
        """Generates a new AES-256 key via Fernet."""
        return Fernet.generate_key()

    @staticmethod
    def store_key(key: bytes) -> bool:
        """Stores the key in the OS keyring."""
        try:
            keyring.set_password(KeyManager.SERVICE_NAME, KeyManager.KEY_ACCOUNT, key.decode('utf-8'))
            return True
        except Exception as e:
            logging.error(f"Failed to store key in keyring: {e}")
            return False

    @staticmethod
    def retrieve_key() -> Optional[bytes]:
        """Retrieves the key from the OS keyring."""
        try:
            key_str = keyring.get_password(KeyManager.SERVICE_NAME, KeyManager.KEY_ACCOUNT)
            if key_str:
                return key_str.encode('utf-8')
            return None
        except Exception as e:
            logging.error(f"Failed to retrieve key from keyring: {e}")
            return None

    @staticmethod
    def key_exists() -> bool:
        """Checks if a key already exists."""
        return KeyManager.retrieve_key() is not None

    @staticmethod
    def store_audit_head(value: str, account: str = AUDIT_HEAD_ACCOUNT) -> bool:
        """Pin the newest audit-chain head in the OS credential store."""
        try:
            keyring.set_password(KeyManager.SERVICE_NAME, account, value)
            return keyring.get_password(KeyManager.SERVICE_NAME, account) == value
        except Exception as exc:
            logging.error("Could not update protected audit-chain anchor: %s", exc)
            return False

    @staticmethod
    def retrieve_audit_head(account: str = AUDIT_HEAD_ACCOUNT) -> Optional[str]:
        try:
            return keyring.get_password(KeyManager.SERVICE_NAME, account)
        except Exception as exc:
            logging.error("Could not read protected audit-chain anchor: %s", exc)
            return None

    @staticmethod
    def ensure_key(data_exists: bool = False) -> bytes:
        """Load the existing key, or safely provision one for a new installation."""
        key = KeyManager.retrieve_key()
        if key:
            return key

        if data_exists:
            raise RuntimeError(
                "The encryption key is unavailable but encrypted data already exists. "
                "Restore the original key from Windows Credential Manager before continuing."
            )

        new_key = KeyManager.generate_key()
        if not KeyManager.store_key(new_key) or KeyManager.retrieve_key() != new_key:
            raise RuntimeError("Could not securely store and verify the encryption key.")
        return new_key

    @staticmethod
    def rotate_key(db_instance) -> Optional[bytes]:
        """
        Generates a new key. The DB instance must handle re-encryption.
        (Implementation depends on DB capabilities).
        """
        raise NotImplementedError(
            "Key rotation is unavailable until database and vault re-encryption is implemented."
        )

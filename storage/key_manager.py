import keyring
import logging
from typing import Optional
from cryptography.fernet import Fernet
import os

class KeyManager:
    """
    Cryptographic Key Management using Windows DPAPI via keyring.
    Never writes keys to disk in plaintext.
    """
    SERVICE_NAME = 'AlgPIIEngine'
    KEY_ACCOUNT = 'master_key'

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
    def ensure_key() -> bytes:
        """Gets existing key or generates and stores a new one."""
        key = KeyManager.retrieve_key()
        if key:
            return key
        
        logging.info("No master key found. Generating new master key.")
        new_key = KeyManager.generate_key()
        KeyManager.store_key(new_key)
        return new_key

    @staticmethod
    def rotate_key(db_instance) -> Optional[bytes]:
        """
        Generates a new key. The DB instance must handle re-encryption.
        (Implementation depends on DB capabilities).
        """
        new_key = KeyManager.generate_key()
        # Storage re-encryption would happen here before saving the new key
        KeyManager.store_key(new_key)
        return new_key

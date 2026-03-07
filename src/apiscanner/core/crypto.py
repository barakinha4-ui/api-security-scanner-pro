"""
core/crypto.py — Industrial-grade Encryption for Scan Data
Handles AES-256-GCM encryption for findings and reports.
"""
import os
import base64
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

class DataShield:
    """
    Handles encryption and decryption of sensitive scan data.
    Uses AES-256-GCM for authenticated encryption.
    """
    
    def __init__(self, master_key: str):
        self.key = self._derive_key(master_key)
        self.aesgcm = AESGCM(self.key)

    def _derive_key(self, password: str) -> bytes:
        """Derives a 32-byte key from a password using PBKDF2."""
        salt = b'api_scanner_pro_v2_salt' # In production, this should be unique and stored
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        return kdf.derive(password.encode())

    def encrypt(self, data: str) -> str:
        """Encrypts a string and returns a base64 encoded packet (nonce + ciphertext + tag)."""
        nonce = os.urandom(12)
        ciphertext = self.aesgcm.encrypt(nonce, data.encode(), None)
        return base64.b64encode(nonce + ciphertext).decode()

    def decrypt(self, encrypted_data: str) -> str:
        """Decrypts a base64 encoded packet."""
        try:
            raw = base64.b64decode(encrypted_data)
            nonce = raw[:12]
            ciphertext = raw[12:]
            decrypted = self.aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted.decode()
        except Exception:
            return "DEC_ERROR: Invalid Key or Corrupted Data"

# Helper for system encryption state
SYSTEM_KEY = os.getenv("SCANNER_ENCRYPTION_KEY", "CHANGE_ME_NOW_12345!")
shield = DataShield(SYSTEM_KEY)

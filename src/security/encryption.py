"""
Cryptographic Services: Symmetric Encryption for Sensitive Payloads
"""

import base64
import os
from typing import Optional
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class FieldEncryptor:
    """
    Encrypts and decrypts sensitive file payloads, exfiltrated content, and tokens
    using AES-128-CBC with HMAC-SHA256 (Fernet specification).
    """

    def __init__(self, key: Optional[bytes] = None, passphrase: Optional[str] = None):
        if key:
            self._key = key
        elif passphrase:
            salt = b"leakmind_sec_salt_2026"
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            self._key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))
        else:
            self._key = Fernet.generate_key()
            
        self._fernet = Fernet(self._key)

    @property
    def key_str(self) -> str:
        return self._key.decode()

    def encrypt(self, plaintext: str) -> str:
        """Encrypts UTF-8 string into base64 ciphertext."""
        if not plaintext:
            return ""
        return self._fernet.encrypt(plaintext.encode("utf-8")).decode("utf-8")

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts base64 ciphertext back into UTF-8 string."""
        if not ciphertext:
            return ""
        return self._fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")

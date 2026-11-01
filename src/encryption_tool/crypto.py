from __future__ import annotations

import os
from typing import Final

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12  # Standard 96-bit nonce for AES-GCM
KEY_SIZE: Final[int] = 32  # 256 bits


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit encryption key using Scrypt."""
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=2**14,
        r=8,
        p=1,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_data(plaintext: bytes, password: str) -> bytes:
    """Encrypt payload data using AES-256-GCM with a derived key."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    # Pack salt + nonce + ciphertext together
    return salt + nonce + ciphertext


def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """Decrypt payload data, validating authentication tags."""
    if len(encrypted_payload) < SALT_SIZE + NONCE_SIZE:
        raise ValueError("Encrypted payload is malformed or truncated.")

    salt = encrypted_payload[:SALT_SIZE]
    nonce = encrypted_payload[SALT_SIZE : SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_payload[SALT_SIZE + NONCE_SIZE :]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)

    return aesgcm.decrypt(nonce, ciphertext, associated_data=None)

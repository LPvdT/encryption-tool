from __future__ import annotations

import os
from typing import Final, Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AlgorithmType = Literal["AES-256-GCM", "ChaCha20-Poly1305"]

SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
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


def encrypt_data(
    plaintext: bytes, password: str, algorithm: AlgorithmType = "AES-256-GCM"
) -> bytes:
    """Encrypt payload data using AES-256-GCM or ChaCha20-Poly1305."""
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = _derive_key(password, salt)

    cipher = ChaCha20Poly1305(key) if algorithm == "ChaCha20-Poly1305" else AESGCM(key)

    ciphertext = cipher.encrypt(nonce, plaintext, associated_data=None)

    # Prepend algorithm flag byte, salt, and nonce to payload
    # 'A' for AES-256-GCM, 'C' for ChaCha20-Poly1305
    algo_flag = b"A" if algorithm == "AES-256-GCM" else b"C"

    return algo_flag + salt + nonce + ciphertext


def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """Decrypt payload data, automatically detecting the algorithm used."""
    if len(encrypted_payload) < 1 + SALT_SIZE + NONCE_SIZE:
        raise ValueError("Encrypted payload is malformed or truncated.")

    algo_flag = encrypted_payload[:1]
    salt = encrypted_payload[1 : 1 + SALT_SIZE]
    nonce = encrypted_payload[1 + SALT_SIZE : 1 + SALT_SIZE + NONCE_SIZE]
    ciphertext = encrypted_payload[1 + SALT_SIZE + NONCE_SIZE :]

    key = _derive_key(password, salt)

    if algo_flag == b"C":
        cipher = ChaCha20Poly1305(key)
    elif algo_flag == b"A":
        cipher = AESGCM(key)
    else:
        raise ValueError("Unknown or unsupported encryption algorithm marker.")

    return cipher.decrypt(nonce, ciphertext, associated_data=None)

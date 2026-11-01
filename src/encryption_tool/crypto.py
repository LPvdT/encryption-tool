from __future__ import annotations

import os
import struct
from typing import Final, Literal

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

AlgorithmType = Literal["AES-256-GCM", "ChaCha20-Poly1305"]

MAGIC: Final[bytes] = b"ETK2"
FORMAT_VERSION: Final[int] = 1
SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
KEY_SIZE: Final[int] = 32
TAG_SIZE: Final[int] = 16

# Argon2id parameters are deliberately fixed in this format version. Changing
# them requires a new format version or an explicitly encoded, bounded profile.
ARGON2_MEMORY_COST: Final[int] = 64 * 1024  # KiB (64 MiB)
ARGON2_ITERATIONS: Final[int] = 3
ARGON2_LANES: Final[int] = 4

_ALGORITHM_IDS: Final[dict[AlgorithmType, int]] = {
    "AES-256-GCM": 1,
    "ChaCha20-Poly1305": 2,
}
_HEADER_PREFIX = struct.Struct(">4sBBB")


class EncryptionError(ValueError):
    """Raised when an encrypted payload cannot be safely processed."""


def _validate_password(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    encoded = password.encode("utf-8")
    if len(encoded) > 1024 * 1024:
        raise ValueError("Password is unreasonably large.")
    return encoded


def _derive_argon2id_key(password: bytes, salt: bytes) -> bytes:
    kdf = Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST,
    )
    return kdf.derive(password)


def _derive_legacy_key(password: bytes, salt: bytes) -> bytes:
    """Read-only compatibility path for the original v2.0 payload format."""
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**14, r=8, p=1).derive(password)


def _cipher(algorithm_id: int, key: bytes) -> AESGCM | ChaCha20Poly1305:
    if algorithm_id == 1:
        return AESGCM(key)
    if algorithm_id == 2:
        return ChaCha20Poly1305(key)
    raise EncryptionError("Unsupported encryption algorithm.")


def encrypt_data(
    plaintext: bytes,
    password: str,
    algorithm: AlgorithmType = "AES-256-GCM",
) -> bytes:
    """Encrypt bytes in the authenticated ETK2 v1 envelope.

    The complete header is authenticated as AEAD associated data. The returned
    envelope is self-describing and remains compatible with decrypt_data().
    """
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes.")
    if algorithm not in _ALGORITHM_IDS:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm!r}")

    password_bytes = _validate_password(password)
    algorithm_id = _ALGORITHM_IDS[algorithm]
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = (
        _HEADER_PREFIX.pack(MAGIC, FORMAT_VERSION, algorithm_id, 1)
        + salt
        + nonce
    )
    key = _derive_argon2id_key(password_bytes, salt)
    return header + _cipher(algorithm_id, key).encrypt(nonce, plaintext, header)


def _decrypt_legacy(payload: bytes, password: bytes) -> bytes:
    minimum_size = 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(payload) < minimum_size:
        raise EncryptionError("Encrypted payload is malformed or truncated.")

    marker = payload[0]
    algorithm_id = {ord("A"): 1, ord("C"): 2}.get(marker)
    if algorithm_id is None:
        raise EncryptionError("Unsupported encrypted payload format.")

    salt = payload[1 : 1 + SALT_SIZE]
    nonce_start = 1 + SALT_SIZE
    nonce = payload[nonce_start : nonce_start + NONCE_SIZE]
    ciphertext = payload[nonce_start + NONCE_SIZE :]
    key = _derive_legacy_key(password, salt)
    try:
        return _cipher(algorithm_id, key).decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise EncryptionError("Decryption failed: incorrect password or damaged data.") from exc


def decrypt_data(encrypted_payload: bytes, password: str) -> bytes:
    """Decrypt ETK2 v1 payloads and legacy v2.0 payloads.

    Authentication failures intentionally use one generic error so callers
    cannot distinguish an incorrect password from modified ciphertext.
    """
    if not isinstance(encrypted_payload, bytes):
        raise TypeError("encrypted_payload must be bytes.")
    password_bytes = _validate_password(password)

    if not encrypted_payload.startswith(MAGIC):
        return _decrypt_legacy(encrypted_payload, password_bytes)

    minimum_size = _HEADER_PREFIX.size + SALT_SIZE + NONCE_SIZE + TAG_SIZE
    if len(encrypted_payload) < minimum_size:
        raise EncryptionError("Encrypted payload is malformed or truncated.")

    magic, version, algorithm_id, kdf_id = _HEADER_PREFIX.unpack_from(encrypted_payload)
    if magic != MAGIC or version != FORMAT_VERSION:
        raise EncryptionError("Unsupported encrypted payload version.")
    if kdf_id != 1:
        raise EncryptionError("Unsupported key derivation function.")
    if algorithm_id not in (1, 2):
        raise EncryptionError("Unsupported encryption algorithm.")

    salt_start = _HEADER_PREFIX.size
    salt = encrypted_payload[salt_start : salt_start + SALT_SIZE]
    nonce_start = salt_start + SALT_SIZE
    nonce = encrypted_payload[nonce_start : nonce_start + NONCE_SIZE]
    header = encrypted_payload[: nonce_start + NONCE_SIZE]
    ciphertext = encrypted_payload[len(header) :]
    key = _derive_argon2id_key(password_bytes, salt)

    try:
        return _cipher(algorithm_id, key).decrypt(nonce, ciphertext, header)
    except InvalidTag as exc:
        raise EncryptionError(
            "Decryption failed: incorrect password or damaged data."
        ) from exc

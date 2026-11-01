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
KEY_MAGIC: Final[bytes] = b"ETK3"
FORMAT_VERSION: Final[int] = 1
SALT_SIZE: Final[int] = 16
NONCE_SIZE: Final[int] = 12
KEY_SIZE: Final[int] = 32
TAG_SIZE: Final[int] = 16
ARGON2_MEMORY_COST: Final[int] = 65536
ARGON2_ITERATIONS: Final[int] = 3
ARGON2_LANES: Final[int] = 4
_IDS: Final[dict[AlgorithmType, int]] = {"AES-256-GCM": 1, "ChaCha20-Poly1305": 2}
_HEADER = struct.Struct(">4sBBB")
_KEY_HEADER = struct.Struct(">4sBB")


class EncryptionError(ValueError):
    pass


def _validate_password(password: str) -> bytes:
    if not isinstance(password, str) or not password:
        raise ValueError("Password must be a non-empty string.")
    value = password.encode()
    if len(value) > 1024 * 1024:
        raise ValueError("Password is unreasonably large.")
    return value


def _derive_argon2id_key(password: bytes, salt: bytes) -> bytes:
    return Argon2id(
        salt=salt,
        length=KEY_SIZE,
        iterations=ARGON2_ITERATIONS,
        lanes=ARGON2_LANES,
        memory_cost=ARGON2_MEMORY_COST,
    ).derive(password)


def _derive_legacy_key(password: bytes, salt: bytes) -> bytes:
    return Scrypt(salt=salt, length=KEY_SIZE, n=2**14, r=8, p=1).derive(password)


def _cipher(algorithm_id: int, key: bytes):
    if algorithm_id == 1:
        return AESGCM(key)
    if algorithm_id == 2:
        return ChaCha20Poly1305(key)
    raise EncryptionError("Unsupported encryption algorithm.")


def encrypt_data(
    plaintext: bytes, password: str, algorithm: AlgorithmType = "AES-256-GCM"
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes.")
    if algorithm not in _IDS:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm!r}")
    pwd = _validate_password(password)
    aid = _IDS[algorithm]
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    header = _HEADER.pack(MAGIC, FORMAT_VERSION, aid, 1) + salt + nonce
    return header + _cipher(aid, _derive_argon2id_key(pwd, salt)).encrypt(nonce, plaintext, header)


def encrypt_data_with_key(
    plaintext: bytes, key: bytes, algorithm: AlgorithmType = "AES-256-GCM"
) -> bytes:
    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes.")
    if len(key) != KEY_SIZE:
        raise ValueError("Key must contain exactly 32 bytes.")
    if algorithm not in _IDS:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm!r}")
    aid = _IDS[algorithm]
    nonce = os.urandom(NONCE_SIZE)
    header = _KEY_HEADER.pack(KEY_MAGIC, FORMAT_VERSION, aid) + nonce
    return header + _cipher(aid, key).encrypt(nonce, plaintext, header)


def decrypt_data_with_key(payload: bytes, key: bytes) -> bytes:
    if len(key) != KEY_SIZE:
        raise ValueError("Key must contain exactly 32 bytes.")
    if len(payload) < _KEY_HEADER.size + NONCE_SIZE + TAG_SIZE:
        raise EncryptionError("Malformed raw-key payload.")
    magic, version, aid = _KEY_HEADER.unpack_from(payload)
    if magic != KEY_MAGIC or version != FORMAT_VERSION or aid not in (1, 2):
        raise EncryptionError("Unsupported raw-key format.")
    start = _KEY_HEADER.size
    nonce = payload[start : start + NONCE_SIZE]
    header = payload[: start + NONCE_SIZE]
    try:
        return _cipher(aid, key).decrypt(nonce, payload[len(header) :], header)
    except InvalidTag as exc:
        raise EncryptionError("Decryption failed: incorrect key or damaged data.") from exc


def decrypt_data(payload: bytes, password: str) -> bytes:
    if not isinstance(payload, bytes):
        raise TypeError("payload must be bytes.")
    pwd = _validate_password(password)
    if not payload.startswith(MAGIC):
        if len(payload) < 1 + SALT_SIZE + NONCE_SIZE + TAG_SIZE:
            raise EncryptionError("Malformed legacy payload.")
        aid = {ord("A"): 1, ord("C"): 2}.get(payload[0])
        if aid is None:
            raise EncryptionError("Unsupported legacy payload.")
        salt = payload[1:17]
        nonce = payload[17:29]
        try:
            return _cipher(aid, _derive_legacy_key(pwd, salt)).decrypt(nonce, payload[29:], None)
        except InvalidTag as exc:
            raise EncryptionError("Decryption failed: incorrect password or damaged data.") from exc
    if len(payload) < _HEADER.size + SALT_SIZE + NONCE_SIZE + TAG_SIZE:
        raise EncryptionError("Malformed ETK2 payload.")
    _, version, aid, kdf = _HEADER.unpack_from(payload)
    if version != FORMAT_VERSION or aid not in (1, 2) or kdf != 1:
        raise EncryptionError("Unsupported ETK2 parameters.")
    salt = payload[7:23]
    nonce = payload[23:35]
    header = payload[:35]
    try:
        return _cipher(aid, _derive_argon2id_key(pwd, salt)).decrypt(nonce, payload[35:], header)
    except InvalidTag as exc:
        raise EncryptionError("Decryption failed: incorrect password or damaged data.") from exc

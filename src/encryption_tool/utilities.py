from __future__ import annotations

import hashlib
import hmac
import secrets
import string
from pathlib import Path
from typing import Final

HASH_ALGORITHMS: Final[tuple[str, ...]] = ("sha256", "sha3_256", "sha512", "blake2b")


def hash_file(path: str | Path, algorithm: str = "sha256") -> str:
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    digest = hashlib.new(algorithm)
    with Path(path).open("rb") as file:
        for block in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    if algorithm not in HASH_ALGORITHMS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    return hashlib.new(algorithm, data).hexdigest()


def hmac_bytes(data: bytes, key: bytes, algorithm: str = "sha256") -> str:
    if algorithm not in ("sha256", "sha512"):
        raise ValueError("HMAC supports SHA-256 and SHA-512.")
    return hmac.new(key, data, algorithm).hexdigest()


def verify_hmac(data: bytes, key: bytes, expected: str, algorithm: str = "sha256") -> bool:
    try:
        actual = hmac_bytes(data, key, algorithm)
        return hmac.compare_digest(actual, expected.lower())
    except ValueError:
        return False


def generate_passphrase(
    length: int = 32, *, uppercase: bool = True, lowercase: bool = True,
    digits: bool = True, symbols: bool = True,
) -> str:
    if not 8 <= length <= 256:
        raise ValueError("Password length must be between 8 and 256.")
    pools = []
    if uppercase:
        pools.append(string.ascii_uppercase)
    if lowercase:
        pools.append(string.ascii_lowercase)
    if digits:
        pools.append(string.digits)
    if symbols:
        pools.append("!@#$%^&*()-_=+[]{}:,.?")
    if not pools:
        raise ValueError("At least one character class must be enabled.")
    if len(pools) > length:
        raise ValueError("Length is too short for selected character classes.")
    alphabet = "".join(pools)
    chars = [secrets.choice(pool) for pool in pools]
    chars.extend(secrets.choice(alphabet) for _ in range(length - len(chars)))
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def random_bytes(length: int = 32) -> bytes:
    if not 1 <= length <= 1024 * 1024:
        raise ValueError("Length must be between 1 byte and 1 MiB.")
    return secrets.token_bytes(length)

from __future__ import annotations

import hashlib
import os
import secrets
from pathlib import Path

KEY_SIZE = 32


def generate_key(path: str | Path, *, overwrite: bool = False) -> Path:
    destination = Path(path)
    if destination.exists() and not overwrite:
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    data = secrets.token_bytes(KEY_SIZE)
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if overwrite else os.O_EXCL)
    descriptor = os.open(destination, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(data)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        destination.unlink(missing_ok=True)
        raise
    if os.name == "nt":
        # Windows ACLs, not POSIX mode bits, govern access on NTFS.
        os.chmod(destination, 0o600)
    return destination


def load_key(path: str | Path) -> bytes:
    key = Path(path).read_bytes()
    if len(key) != KEY_SIZE:
        raise ValueError("Key file must contain exactly 32 raw bytes.")
    return key


def key_fingerprint(key: bytes) -> str:
    if len(key) != KEY_SIZE:
        raise ValueError("Key must contain exactly 32 bytes.")
    return hashlib.sha256(key).hexdigest()


def inspect_key(path: str | Path) -> dict[str, str]:
    key = load_key(path)
    return {"path": str(Path(path)), "fingerprint": key_fingerprint(key), "size": str(len(key))}

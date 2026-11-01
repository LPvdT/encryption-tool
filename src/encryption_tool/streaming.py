from __future__ import annotations

import os
import struct
import tempfile
import threading
from collections.abc import Callable
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag

from encryption_tool.crypto import EncryptionError, _cipher, _derive_argon2id_key, _validate_password

MAGIC = b"ETFS"
VERSION = 1
SALT_SIZE = 16
PREFIX_SIZE = 8
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024
MIN_CHUNK_SIZE = 4096
MAX_CHUNK_SIZE = 16 * 1024 * 1024
_HEADER = struct.Struct(">4sBBBI")
_RECORD = struct.Struct(">BI")
_ALGORITHMS = {"AES-256-GCM": 1, "ChaCha20-Poly1305": 2}
Progress = Callable[[int, int], None]


class OperationCancelled(InterruptedError):
    """Raised when a caller requests cancellation."""


def _check_cancel(cancel: threading.Event | None) -> None:
    if cancel is not None and cancel.is_set():
        raise OperationCancelled("Operation cancelled.")


def _nonce(prefix: bytes, counter: int) -> bytes:
    if counter >= 2**32:
        raise EncryptionError("File exceeds the supported authenticated chunk count.")
    return prefix + counter.to_bytes(4, "big")


def _temporary_output(destination: Path) -> tuple[BinaryIO, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    handle = tempfile.NamedTemporaryFile(
        mode="wb", prefix=f".{destination.name}.", suffix=".tmp",
        dir=destination.parent, delete=False
    )
    return handle, Path(handle.name)


def _publish(temporary: Path, destination: Path, overwrite: bool) -> None:
    if overwrite:
        os.replace(temporary, destination)
    else:
        os.link(temporary, destination)
        temporary.unlink()


def encrypt_file(
    source: str | Path, destination: str | Path, password: str,
    algorithm: str = "AES-256-GCM", chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False, progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> Path:
    source_path, destination_path = Path(source), Path(destination)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if source_path.resolve() == destination_path.resolve():
        raise ValueError("Input and output paths must be different.")
    if destination_path.exists() and not overwrite:
        raise FileExistsError(destination_path)
    if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
        raise ValueError(f"chunk_size must be between {MIN_CHUNK_SIZE} and {MAX_CHUNK_SIZE}.")
    if algorithm not in _ALGORITHMS:
        raise ValueError(f"Unsupported encryption algorithm: {algorithm!r}")

    password_bytes = _validate_password(password)
    total = source_path.stat().st_size
    salt, prefix = os.urandom(SALT_SIZE), os.urandom(PREFIX_SIZE)
    algorithm_id = _ALGORITHMS[algorithm]
    header = _HEADER.pack(MAGIC, VERSION, algorithm_id, 1, chunk_size) + salt + prefix
    cipher = _cipher(algorithm_id, _derive_argon2id_key(password_bytes, salt))
    output, temporary = _temporary_output(destination_path)
    processed = counter = 0
    try:
        with source_path.open("rb") as input_file, output:
            output.write(header)
            while block := input_file.read(chunk_size):
                _check_cancel(cancel)
                record = _RECORD.pack(0, len(block))
                output.write(record)
                output.write(cipher.encrypt(_nonce(prefix, counter), block, header + record))
                counter += 1
                processed += len(block)
                if progress:
                    progress(processed, total)
            _check_cancel(cancel)
            final_record = _RECORD.pack(1, 0)
            output.write(final_record)
            output.write(cipher.encrypt(_nonce(prefix, counter), b"", header + final_record))
            output.flush()
            os.fsync(output.fileno())
        _check_cancel(cancel)
        _publish(temporary, destination_path, overwrite)
        if progress:
            progress(total, total)
        return destination_path
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def decrypt_file(
    source: str | Path, destination: str | Path, password: str,
    overwrite: bool = False, progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> Path:
    source_path, destination_path = Path(source), Path(destination)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if source_path.resolve() == destination_path.resolve():
        raise ValueError("Input and output paths must be different.")
    if destination_path.exists() and not overwrite:
        raise FileExistsError(destination_path)

    password_bytes = _validate_password(password)
    total = source_path.stat().st_size
    output, temporary = _temporary_output(destination_path)
    processed = 0
    try:
        with source_path.open("rb") as input_file, output:
            fixed_size = _HEADER.size + SALT_SIZE + PREFIX_SIZE
            header = input_file.read(fixed_size)
            if len(header) != fixed_size:
                raise EncryptionError("Encrypted file header is truncated.")
            magic, version, algorithm_id, kdf_id, chunk_size = _HEADER.unpack_from(header)
            if magic != MAGIC or version != VERSION or kdf_id != 1:
                raise EncryptionError("Unsupported encrypted file format.")
            if algorithm_id not in (1, 2):
                raise EncryptionError("Unsupported encryption algorithm.")
            if not MIN_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
                raise EncryptionError("Invalid encrypted file chunk size.")
            salt = header[_HEADER.size : _HEADER.size + SALT_SIZE]
            prefix = header[-PREFIX_SIZE:]
            cipher = _cipher(algorithm_id, _derive_argon2id_key(password_bytes, salt))
            counter = 0

            while True:
                _check_cancel(cancel)
                record = input_file.read(_RECORD.size)
                if len(record) != _RECORD.size:
                    raise EncryptionError("Encrypted file is truncated or has no final record.")
                record_type, length = _RECORD.unpack(record)
                if record_type == 0 and not 1 <= length <= chunk_size:
                    raise EncryptionError("Invalid encrypted chunk length.")
                if record_type == 1 and length != 0:
                    raise EncryptionError("Invalid final record.")
                if record_type not in (0, 1):
                    raise EncryptionError("Unknown encrypted record type.")
                encrypted_length = length + TAG_SIZE
                encrypted = input_file.read(encrypted_length)
                if len(encrypted) != encrypted_length:
                    raise EncryptionError("Encrypted chunk is truncated.")
                try:
                    plaintext = cipher.decrypt(_nonce(prefix, counter), encrypted, header + record)
                except InvalidTag as exc:
                    raise EncryptionError("Decryption failed: incorrect password or damaged data.") from exc
                counter += 1
                processed += _RECORD.size + encrypted_length
                if record_type == 1:
                    if plaintext or input_file.read(1):
                        raise EncryptionError("Invalid data after authenticated final record.")
                    break
                output.write(plaintext)
                if progress:
                    progress(processed, total)
            output.flush()
            os.fsync(output.fileno())
        _check_cancel(cancel)
        _publish(temporary, destination_path, overwrite)
        if progress:
            progress(total, total)
        return destination_path
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _walk_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_file():
            yield path


def encrypt_directory(
    source: str | Path, destination: str | Path, password: str,
    algorithm: str = "AES-256-GCM", overwrite: bool = False,
    progress: Progress | None = None, cancel: threading.Event | None = None,
) -> list[Path]:
    root, target = Path(source), Path(destination)
    if not root.is_dir():
        raise NotADirectoryError(root)
    if target.resolve() == root.resolve() or root.resolve() in target.resolve().parents:
        raise ValueError("Destination directory cannot be inside the source directory.")
    files = list(_walk_files(root))
    total = sum(p.stat().st_size for p in files)
    completed = 0
    outputs = []
    for path in files:
        _check_cancel(cancel)
        relative = path.relative_to(root)
        output = target / relative.parent / f"{relative.name}.etfs"
        def update(done: int, _size: int, base: int = completed) -> None:
            if progress:
                progress(base + done, total)
        outputs.append(encrypt_file(path, output, password, algorithm, overwrite=overwrite, progress=update, cancel=cancel))
        completed += path.stat().st_size
    if progress:
        progress(total, total)
    return outputs


def decrypt_directory(
    source: str | Path, destination: str | Path, password: str,
    overwrite: bool = False, progress: Progress | None = None,
    cancel: threading.Event | None = None,
) -> list[Path]:
    root, target = Path(source), Path(destination)
    if not root.is_dir():
        raise NotADirectoryError(root)
    if target.resolve() == root.resolve() or root.resolve() in target.resolve().parents:
        raise ValueError("Destination directory cannot be inside the source directory.")
    files = [p for p in sorted(root.rglob("*.etfs")) if not p.is_symlink()]
    total = sum(p.stat().st_size for p in files)
    completed = 0
    outputs = []
    for path in files:
        _check_cancel(cancel)
        relative = path.relative_to(root)
        output = target / relative.parent / relative.name.removesuffix(".etfs")
        def update(done: int, _size: int, base: int = completed) -> None:
            if progress:
                progress(base + done, total)
        outputs.append(decrypt_file(path, output, password, overwrite=overwrite, progress=update, cancel=cancel))
        completed += path.stat().st_size
    if progress:
        progress(total, total)
    return outputs


def inspect_file(path: str | Path) -> dict[str, object]:
    """Read unauthenticated format metadata; this does not verify the password/tag."""
    file_path = Path(path)
    with file_path.open("rb") as stream:
        prefix = stream.read(64)
    if prefix.startswith(b"ETFS") and len(prefix) >= _HEADER.size + SALT_SIZE + PREFIX_SIZE:
        magic, version, algorithm_id, kdf_id, chunk_size = _HEADER.unpack_from(prefix)
        return {
            "format": "ETFS", "version": version,
            "algorithm": {1: "AES-256-GCM", 2: "ChaCha20-Poly1305"}.get(algorithm_id, "unknown"),
            "kdf": {1: "Argon2id"}.get(kdf_id, "unknown"),
            "chunk_size": chunk_size, "file_size": file_path.stat().st_size,
            "authenticated": False,
        }
    if prefix.startswith(b"ETK2") and len(prefix) >= 7:
        return {
            "format": "ETK2", "version": prefix[4],
            "algorithm": {1: "AES-256-GCM", 2: "ChaCha20-Poly1305"}.get(prefix[5], "unknown"),
            "kdf": "Argon2id" if prefix[6] == 1 else "unknown",
            "file_size": file_path.stat().st_size, "authenticated": False,
        }
    return {"format": "unknown", "file_size": file_path.stat().st_size, "authenticated": False}

from __future__ import annotations

import os
import struct
import tempfile
from pathlib import Path
from typing import BinaryIO

from cryptography.exceptions import InvalidTag

from encryption_tool.crypto import (
    EncryptionError,
    _cipher,
    _derive_argon2id_key,
    _validate_password,
)

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
        # A hard link is an atomic no-clobber publication on the same filesystem.
        os.link(temporary, destination)
        temporary.unlink()


def encrypt_file(
    source: str | Path,
    destination: str | Path,
    password: str,
    algorithm: str = "AES-256-GCM",
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    overwrite: bool = False,
) -> Path:
    """Encrypt a file as authenticated records without buffering the whole file."""
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
    salt, prefix = os.urandom(SALT_SIZE), os.urandom(PREFIX_SIZE)
    algorithm_id = _ALGORITHMS[algorithm]
    header = _HEADER.pack(MAGIC, VERSION, algorithm_id, 1, chunk_size) + salt + prefix
    cipher = _cipher(algorithm_id, _derive_argon2id_key(password_bytes, salt))
    output, temporary = _temporary_output(destination_path)
    counter = 0
    try:
        with source_path.open("rb") as input_file, output:
            output.write(header)
            while block := input_file.read(chunk_size):
                record = _RECORD.pack(0, len(block))
                output.write(record)
                output.write(cipher.encrypt(_nonce(prefix, counter), block, header + record))
                counter += 1
            final_record = _RECORD.pack(1, 0)
            output.write(final_record)
            output.write(cipher.encrypt(_nonce(prefix, counter), b"", header + final_record))
            output.flush()
            os.fsync(output.fileno())
        _publish(temporary, destination_path, overwrite)
        return destination_path
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def decrypt_file(
    source: str | Path,
    destination: str | Path,
    password: str,
    overwrite: bool = False,
) -> Path:
    """Decrypt and authenticate each record; publish output only after final tag."""
    source_path, destination_path = Path(source), Path(destination)
    if not source_path.is_file():
        raise FileNotFoundError(source_path)
    if source_path.resolve() == destination_path.resolve():
        raise ValueError("Input and output paths must be different.")
    if destination_path.exists() and not overwrite:
        raise FileExistsError(destination_path)

    password_bytes = _validate_password(password)
    output, temporary = _temporary_output(destination_path)
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
                record = input_file.read(_RECORD.size)
                if len(record) != _RECORD.size:
                    raise EncryptionError("Encrypted file is truncated or has no final record.")
                record_type, length = _RECORD.unpack(record)
                if record_type == 0:
                    if not 1 <= length <= chunk_size:
                        raise EncryptionError("Invalid encrypted chunk length.")
                elif record_type == 1:
                    if length != 0:
                        raise EncryptionError("Invalid final record.")
                else:
                    raise EncryptionError("Unknown encrypted record type.")

                encrypted_length = length + TAG_SIZE
                encrypted = input_file.read(encrypted_length)
                if len(encrypted) != encrypted_length:
                    raise EncryptionError("Encrypted chunk is truncated.")
                try:
                    plaintext = cipher.decrypt(
                        _nonce(prefix, counter), encrypted, header + record
                    )
                except InvalidTag as exc:
                    raise EncryptionError(
                        "Decryption failed: incorrect password or damaged data."
                    ) from exc
                counter += 1

                if record_type == 1:
                    if plaintext or input_file.read(1):
                        raise EncryptionError("Invalid data after authenticated final record.")
                    break
                output.write(plaintext)

            output.flush()
            os.fsync(output.fileno())
        _publish(temporary, destination_path, overwrite)
        return destination_path
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def encrypt_directory(
    source: str | Path,
    destination: str | Path,
    password: str,
    algorithm: str = "AES-256-GCM",
    overwrite: bool = False,
) -> list[Path]:
    """Encrypt each regular file recursively, preserving relative paths."""
    root, target = Path(source), Path(destination)
    if not root.is_dir():
        raise NotADirectoryError(root)
    outputs: list[Path] = []
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            continue
        if path.is_file():
            relative = path.relative_to(root)
            output = target / relative.parent / f"{relative.name}.etfs"
            outputs.append(encrypt_file(path, output, password, algorithm, overwrite=overwrite))
    return outputs


def decrypt_directory(
    source: str | Path,
    destination: str | Path,
    password: str,
    overwrite: bool = False,
) -> list[Path]:
    """Decrypt all .etfs files recursively, preserving relative paths."""
    root, target = Path(source), Path(destination)
    if not root.is_dir():
        raise NotADirectoryError(root)
    outputs: list[Path] = []
    for path in sorted(root.rglob("*.etfs")):
        if path.is_symlink():
            continue
        relative = path.relative_to(root)
        output = target / relative.parent / relative.name.removesuffix(".etfs")
        outputs.append(decrypt_file(path, output, password, overwrite=overwrite))
    return outputs

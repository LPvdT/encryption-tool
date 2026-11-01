# Encryption Tool

A cross-platform terminal security toolkit for password- and key-based authenticated encryption, file operations and integrity utilities.

## Features

- ETK2 versioned password envelope: Argon2id (64 MiB, 3 iterations, 4 lanes), AES-256-GCM or ChaCha20-Poly1305. Legacy v2.0 Scrypt payloads remain decryptable.
- ETK3 raw-key payload envelope. Generate 256-bit keys with `encrypt-tool-cli keygen`; keys are raw binary files and must be protected with OS permissions/ACLs.
- ETFS streaming file format: bounded chunks, unique per-record nonces, AEAD authentication and authenticated final record. Truncation, reordering, tampering and appended bytes are rejected.
- Single files, recursive directories and batch file workflows. Temporary outputs are discarded on cancellation or failure; destinations are not overwritten by default.
- Progress callbacks and cooperative cancellation in the Python streaming API.
- Textual UI with dashboard/sidebar, responsive layouts, shortcuts, workers, operation history, key utilities and file inspection.
- CLI: encrypt/decrypt, directory/batch operations, hashing, HMAC, key generation, inspection and password generation.
- SHA-256, SHA3-256, SHA-512 and BLAKE2b; HMAC-SHA-256 / HMAC-SHA-512.
- TOML configuration using platform-specific config directories.

## Install

```bash
uv sync
uv run encrypt-tool
uv run encrypt-tool-cli --help
```

## CLI examples

```bash
encrypt-tool-cli encrypt ./archive.zip ./archive.zip.etfs
encrypt-tool-cli decrypt ./archive.zip.etfs ./archive.zip
encrypt-tool-cli encrypt-dir ./documents ./documents.encrypted
encrypt-tool-cli batch-encrypt ./selected-files ./encrypted
encrypt-tool-cli hash ./archive.zip --algorithm sha256
encrypt-tool-cli keygen ~/.config/encryption-tool/my-key.bin
encrypt-tool-cli key-info ~/.config/encryption-tool/my-key.bin
encrypt-tool-cli hmac ./archive.zip --key ~/.config/encryption-tool/my-key.bin
encrypt-tool-cli inspect ./archive.zip.etfs
encrypt-tool-cli password --length 40
encrypt-tool-cli init-config
```

## Python API

```python
from encryption_tool.crypto import encrypt_data, decrypt_data, encrypt_data_with_key, decrypt_data_with_key
from encryption_tool.streaming import encrypt_file, decrypt_file

payload = encrypt_data(b"binary\\x00data", "long passphrase")
assert decrypt_data(payload, "long passphrase") == b"binary\\x00data"
key_payload = encrypt_data_with_key(b"secret", bytes.fromhex("00" * 32))
assert decrypt_data_with_key(key_payload, bytes.fromhex("00" * 32)) == b"secret"
encrypt_file("large.bin", "large.bin.etfs", "passphrase")
decrypt_file("large.bin.etfs", "recovered.bin", "passphrase")
```

## Formats and security

ETK2 is password-based; ETK3 is raw-key based; ETFS is the streaming file format. ETFS uses a random 64-bit nonce prefix plus a monotonically increasing 32-bit record counter. Every record and the finalization marker are authenticated with AEAD; the fixed header and record descriptors are associated data. Argon2id parameters are fixed and are not read from untrusted payload fields.

Inspection reports unauthenticated header metadata only. A successful decryption verifies the authentication tag. Hashes are unkeyed checksums; use HMAC when keyed authenticity is required.

ETFS is a custom record protocol and has not received independent cryptographic review. Do not rely on it for high-value data until reviewed. Directory operations are per-file, not transactional as a whole; earlier completed files remain if a later file fails. Empty directories and filesystem metadata are not preserved. Cancellation is cooperative and leaves already completed directory entries in place. Secure deletion is not attempted.

Key files contain raw key material. Restrict access using OS ACLs, maintain secure backups, and never commit them to source control. Windows uses NTFS ACLs; POSIX systems use owner-only mode bits where supported.

## Configuration

Run `encrypt-tool-cli init-config` to create a default TOML config in the platform config directory. Settings are validated and bounded on load. History stores operation metadata only, never passwords, keys or plaintext.

## Development

```bash
uv run pytest
uv run ruff check .
uv run pyrefly check
```

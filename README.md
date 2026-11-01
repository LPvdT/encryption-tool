# Encryption Tool

A keyboard-first terminal security toolkit for authenticated encryption and file
utilities.

## Current capabilities

- Password-based authenticated encryption with AES-256-GCM or ChaCha20-Poly1305.
- Versioned `ETK2` envelope using Argon2id (64 MiB, 3 iterations, 4 lanes).
- Backward-compatible decryption of payloads produced by the original v2.0
  Scrypt-based format.
- Header authentication: format version, algorithm and KDF identifiers are
  covered by the AEAD authentication tag.
- Binary-safe Python API: plaintext and ciphertext are bytes.

## Install

```bash
uv sync
uv run encrypt-tool
```

## Python API

```python
from encryption_tool.crypto import decrypt_data, encrypt_data

encrypted = encrypt_data(b"binary\\x00payload", "use a long passphrase")
plaintext = decrypt_data(encrypted, "use a long passphrase")
assert plaintext == b"binary\\x00payload"
```

## Envelope format

ETK2 v1 is encoded as:

| Field | Size |
|---|---:|
| Magic | 4 bytes |
| Format version | 1 byte |
| Algorithm ID | 1 byte |
| KDF ID | 1 byte |
| Argon2id salt | 16 bytes |
| AEAD nonce | 12 bytes |
| Ciphertext + authentication tag | variable |

The fixed header is supplied as AEAD associated data. Altering any header field
therefore causes authentication to fail. KDF parameters are fixed in v1 rather
than being accepted from untrusted input.

## Security notes

- Use a unique, high-entropy passphrase for each sensitive use.
- The application does not retain passwords or plaintext keys.
- Decryption intentionally reports one generic authentication error for an
  incorrect password or modified ciphertext.
- The current byte-oriented API holds the complete payload in memory. It is
  suitable for text and moderate-sized files, not multi-gigabyte streaming.
  Authenticated chunked file encryption is a separate feature and must use a
  reviewed record protocol with nonce uniqueness and authenticated finalization;
  do not split data into independently encrypted chunks without those controls.
- This project is not a substitute for an independently audited encryption
  product. Review the format and threat model before relying on it for critical
  data.

## Development

```bash
uv run pytest
uv run ruff check .
uv run pyrefly check
```

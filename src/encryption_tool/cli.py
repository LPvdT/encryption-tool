from __future__ import annotations

import argparse
import getpass
import sys
from pathlib import Path

from encryption_tool.crypto import decrypt_data, encrypt_data
from encryption_tool.streaming import decrypt_directory, decrypt_file, encrypt_directory, encrypt_file
from encryption_tool.utilities import HASH_ALGORITHMS, generate_passphrase, hash_file


def _password(confirm: bool = False) -> str:
    password = getpass.getpass("Password: ")
    if confirm and password != getpass.getpass("Confirm password: "):
        raise ValueError("Passwords do not match.")
    return password


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="encrypt-tool-cli",
        description="Authenticated encryption and file-integrity utilities.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    for name in ("encrypt", "decrypt"):
        command = commands.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
        command.add_argument("--overwrite", action="store_true")
        if name == "encrypt":
            command.add_argument(
                "--algorithm",
                choices=("AES-256-GCM", "ChaCha20-Poly1305"),
                default="AES-256-GCM",
            )
    for name in ("encrypt-dir", "decrypt-dir"):
        command = commands.add_parser(name)
        command.add_argument("source", type=Path)
        command.add_argument("destination", type=Path)
        command.add_argument("--overwrite", action="store_true")
        if name == "encrypt-dir":
            command.add_argument(
                "--algorithm",
                choices=("AES-256-GCM", "ChaCha20-Poly1305"),
                default="AES-256-GCM",
            )

    digest = commands.add_parser("hash", help="Hash a file.")
    digest.add_argument("source", type=Path)
    digest.add_argument("--algorithm", choices=HASH_ALGORITHMS, default="sha256")

    password = commands.add_parser("password", help="Generate a secure password.")
    password.add_argument("--length", type=int, default=32)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "encrypt":
            result = encrypt_file(
                args.source, args.destination, _password(confirm=True),
                args.algorithm, overwrite=args.overwrite,
            )
            print(f"Encrypted: {result}")
        elif args.command == "decrypt":
            result = decrypt_file(
                args.source, args.destination, _password(), overwrite=args.overwrite
            )
            print(f"Decrypted: {result}")
        elif args.command == "encrypt-dir":
            results = encrypt_directory(
                args.source, args.destination, _password(), args.algorithm, args.overwrite
            )
            print(f"Encrypted {len(results)} file(s).")
        elif args.command == "decrypt-dir":
            results = decrypt_directory(
                args.source, args.destination, _password(), args.overwrite
            )
            print(f"Decrypted {len(results)} file(s).")
        elif args.command == "hash":
            print(f"{args.algorithm}: {hash_file(args.source, args.algorithm)}")
        elif args.command == "password":
            print(generate_passphrase(args.length))
        return 0
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

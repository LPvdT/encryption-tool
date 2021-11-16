from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

import os
import tarfile
from rich.console import Console
from rich.traceback import install
from typing import Union, Optional

CONSOLE = Console()
install(console=CONSOLE)


def encrypt_targets(
    output_folder: str,
    iterations: Union[int, float],
    key_length: Optional[int] = None,
    salt: Optional[Union[int, float, str]] = None,
    save_key: bool = False,
    **kwargs,
):
    def _auth():
        password = bytes(
            CONSOLE.input(prompt="\nEnter password: ", password=True),
            encoding="utf-8",
        )

        verification = bytes(
            CONSOLE.input(prompt="Verify password: ", password=True),
            encoding="utf-8",
        )

        return (password, verification)

    password, verification = _auth()

    if password != verification:
        while password != verification:
            CONSOLE.print(
                "[bold red]Error:[/bold red] [italic]Passwords do not match.[/italic]"
            )
            password, verification = _auth()

    # Get file buffer
    path_buffer = CONSOLE.input(
        "Enter file locations (comma-separated): "
    ).split(",")
    path_buffer = [p.strip() for p in path_buffer]

    # Parse kwargs
    key_file = "" if "key_file" not in kwargs else kwargs["key_file"]
    key_file = (
        os.path.join(key_file, "keyfile")
        if os.path.splitext(key_file)[1] == ""
        else key_file
    )

    # Parse potential float input
    if isinstance(iterations, float):
        iterations = int(iterations)

    # Parse salt
    if salt:
        if isinstance(salt, float):
            salt = bytes(int(salt))
        elif isinstance(salt, str):
            salt = bytes(salt, encoding="utf-8")
        else:
            salt = salt
    else:
        salt = bytes(420)

    # Parse key length
    if key_length:
        if not key_length <= ((2 ** 32) - 1) * hashes.SHA512().digest_size:
            raise ValueError("key_length is set too large.")

    # Infer target types of paths in buffer
    type_buffer = {
        path: type
        for (path, type) in zip(
            path_buffer,
            [
                "file" if os.path.isfile(p) else "directory"
                for p in path_buffer
            ],
        )
    }

    # Init Key Derivative Function
    if not iterations < int(1e5):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=key_length,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
    else:
        CONSOLE.log(
            f"[bold red]Warning:[/bold red] Iterations of {iterations} is low. Increase the amount to help migigate brute-force attempts."
        )

    # Generate key
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # Save key
    if save_key:
        with open("./keyfile" if not key_file else key_file, "wb") as f:
            f.write(key)

    # Fernet instance
    fernet = Fernet(key=key)

    # Encryption loop
    for target, type in type_buffer.items():

        # If the target is a directory, tarball and gzip it first
        CONSOLE.log(f"Encrypting '{target}'...")

        if type == "directory":

            CONSOLE.log(f"Processing directory '{target}'...")

            tar = tarfile.open(f"{target}.folder", "w:gz")
            tar.add(target, arcname=f"{target}")
            tar.close()

            target = f"{target}.folder"

        # Parse target file
        with open(target, "rb") as f:
            original = f.read()

        # Encrypt target file
        encrypted = fernet.encrypt(original)

        # Write encrypted output
        target_name = os.path.split(target)[-1]

        with open(
            os.path.join(output_folder, target_name + ".crypto"), "wb"
        ) as f:
            f.write(encrypted)

        # Teardown
        if type == "directory" and os.path.exists(f"./{target_name}"):

            CONSOLE.log("Cleaning up iteration temporary files...")
            os.unlink(f"./{target_name}")

        # Vertical seperator
        CONSOLE.print("")

    # Report completion
    CONSOLE.log(
        f"Encryption completed: {len(type_buffer.keys())} targets encrypted."
    )


def decrypt_targets(
    output_folder: str,
    iterations: Union[int, float],
    key_length: Optional[int] = None,
    salt: Optional[Union[int, float, str]] = None,
):

    # Get password
    password = bytes(
        bytes(
            CONSOLE.input(prompt="\nEnter password: ", password=True),
            encoding="utf-8",
        )
    )

    # Get file buffer
    path_buffer = CONSOLE.input(
        "Enter file locations (comma-separated): "
    ).split(",")
    path_buffer = [p.strip() for p in path_buffer]

    # Parse potential float input
    if isinstance(iterations, float):
        iterations = int(iterations)

    # Parse salt
    if salt:
        if isinstance(salt, float):
            salt = bytes(int(salt))
        elif isinstance(salt, str):
            salt = bytes(salt, encoding="utf-8")
        else:
            salt = salt
    else:
        salt = bytes(420)

    # Parse key length
    if key_length:
        if not key_length <= ((2 ** 32) - 1) * hashes.SHA512().digest_size:
            raise ValueError("key_length is set too large.")

    # Init Key Derivative Function
    if not iterations < int(1e5):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
    else:
        CONSOLE.log(
            f"[bold red]Warning:[/bold red] Iterations of {iterations} is low. Increase the amount to help migigate brute-force attempts."
        )

    # Derive key
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # Fernet instance
    fernet = Fernet(key=key)

    # Decryption loop
    for target in path_buffer:

        # Determine target type
        if target.find(".folder") > 0:
            CONSOLE.log(f"Decrypting directory: '{target}'...")
            isdir = True
        else:
            CONSOLE.log(f"Decrypting file: '{target}'...")
            isdir = False

        # Open encrypted target file
        with open(target, "rb") as f:
            encrypted = f.read()

        # Decrypt encrypted file
        decrypted = fernet.decrypt(encrypted)

        # Write decrypted output
        target_name = os.path.splitext(os.path.split(target)[-1])[0]

        with open(os.path.join(output_folder, target_name), "wb") as f:
            f.write(decrypted)

        if isdir:

            CONSOLE.log("Extracting directory...")

            # Extract the compressed target
            tar = tarfile.open(
                os.path.join(output_folder, f"{target_name}"), "r:gz"
            )
            tar.extractall(output_folder)
            tar.close()

            # Delete compressed decrypted file
            os.unlink(os.path.join(output_folder, f"{target_name}"))

        # Vertical seperator
        CONSOLE.print("")

    # Report completion
    CONSOLE.log(f"Decryption completed: {len(path_buffer)} targets decrypted.")


def interface(header: bool = True):

    # Menu
    if header:
        CONSOLE.rule(title="[bold blue]File Encryption Tool")

        CONSOLE.print(
            "\n\t[#B0C4DE]Simple tool to encrypt or decrypt your files and folders using the [italic]SHA-2[/italic] algorithm with [italic]512-bit[/italic] hashing."
        )

    choice = CONSOLE.input(
        prompt="\n\t[blue]1.[/blue] [#778899]Encrypt file(s) or folder(s)[/#778899]\n\t[blue]2.[/blue] [#778899]Decrypt file(s) or folder(s)[/#778899]\n\n\t[blue]-[/blue] [#778899]Type[/#778899] [italic]'quit'[/italic] [#778899]to exit.[/#778899]\n\n"
    )

    # Options
    if choice == "1":
        CONSOLE.rule(title="[bold purple]Encrypt targets")

        encrypt_targets(
            output_folder="./encrypted", iterations=1e6, key_length=32
        )

    elif choice == "2":
        CONSOLE.rule(title="[bold green]Decrypt targets")

        decrypt_targets(
            output_folder="./decrypted", iterations=1e6, key_length=32
        )

    elif choice == "quit":
        CONSOLE.rule(title="[italic #B0C4DE]Application terminated")

    else:
        CONSOLE.rule(title="\n[italic #B0C4DE]Supported options:\n")

        interface(header=False)


if __name__ == "__main__":

    # Ensure folder existence
    os.makedirs("./decrypted", exist_ok=True)
    os.makedirs("./encrypted", exist_ok=True)

    # Start application
    interface()

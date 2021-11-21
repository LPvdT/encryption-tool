from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from rich.console import Console
from rich.traceback import install

from typing import Union, Optional

import os
import base64
import tarfile
import click

CONSOLE = Console()
install(console=CONSOLE)


@click.group()
# All shared args and options here
@click.pass_context
def main(ctx, output_folder: str):
    # All context objects here
    ctx.obj["output_folder"] = output_folder


@click.main(name="encrypt")
@click.option(
    "--output_folder",
    "-o",
    type=str,
    default="./encrypted",
    help="Output folder for encrypted items",
)
@click.option(
    "--iterations",
    "-i",
    type=int,
    default=int(1e6),
    help="Number of algorithm iterations",
)
@click.option(
    "--key-length",
    "-k",
    type=Union[str, int, float],
    default=32,
    help="Bitrate of the key",
)
@click.option(
    "--salt",
    "-s",
    type=Union[str, int, float],
    default=None,
    help="Custom value to use as a salt",
)
@click.option(
    "--save-key",
    "-S",
    type=bool,
    default=False,
    is_flag=True,
    help="Store key file",
)
@click.argument("targets", nargs=-1)
def encrypt_targets(
    output_folder: str,
    iterations: Union[int, float],
    key_length: Optional[int] = None,
    salt: Optional[Union[int, float, str]] = None,
    save_key: bool = False,
    **kwargs,
):
    # Get password
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
    if not "targets" in kwargs:
        path_buffer = CONSOLE.input(
            "Enter file locations (comma-separated): "
        ).split(",")
        path_buffer = [p.strip() for p in path_buffer]
    else:
        path_buffer = kwargs["targets"]

    # Assert output folder existence
    os.makedirs(output_folder, exist_ok=True)

    # Parse remaining kwargs
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


@click.main(name="decrypt")
@click.option(
    "--output_folder",
    "-o",
    default="./decrypted",
    help="Output folder for decrypted items",
)
@click.option(
    "--salt", "-s", default=420, help="Salt used when encrypting (if custom)"
)
@click.argument("targets")
def decrypt_targets(
    output_folder: str, salt: Optional[Union[int, float, str]] = None,
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

    # Assert output folder existence
    os.makedirs(output_folder, exist_ok=True)

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

    # Init Key Derivative Function
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(), salt=salt, backend=default_backend(),
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


def start():
    main(obj=dict)


if __name__ == "__main__":

    # Start application
    start()

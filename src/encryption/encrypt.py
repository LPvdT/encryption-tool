from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from typing import Union, Optional

import os
import base64
import tarfile

from .crypto import CryptoEngine


class Encryptor(CryptoEngine):
    def __init__(self) -> None:
        super().__init__()

    def encrypt_targets(
        self,
        output_folder: str,
        iterations: Union[int, float],
        salt: Optional[Union[int, float, str]] = None,
        save_key: bool = False,
        **kwargs,
    ):
        # Get file buffer
        if not "targets" in kwargs:
            path_buffer = self.CONSOLE.input(
                "Enter file locations (comma-separated): "
            ).split(",")
            path_buffer = [p.strip() for p in path_buffer]
        else:
            path_buffer = kwargs["targets"]

        # Get password
        def _auth():
            password = bytes(
                self.CONSOLE.input(prompt="Enter password: ", password=True),
                encoding="utf-8",
            )

            verification = bytes(
                self.CONSOLE.input(prompt="Verify password: ", password=True),
                encoding="utf-8",
            )

            return (password, verification)

        password, verification = _auth()

        if password != verification:
            while password != verification:
                self.CONSOLE.print(
                    "[bold red]Error:[/bold red] [italic]Passwords do not match.[/italic]"
                )
                password, verification = _auth()

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
                length=32,
                salt=salt,
                iterations=iterations,
                backend=default_backend(),
            )
        else:
            self.CONSOLE.log(
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
            self.CONSOLE.log(f"Encrypting '{target}'...")

            if type == "directory":

                self.CONSOLE.log(f"Processing directory '{target}'...")

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

            os.makedirs(output_folder, exist_ok=True)

            with open(
                os.path.join(output_folder, target_name + ".crypto"), "wb",
            ) as f:
                f.write(encrypted)

            # Teardown
            if type == "directory" and os.path.exists(f"./{target_name}"):

                self.CONSOLE.log("Cleaning up iteration temporary files...")
                os.unlink(f"./{target_name}")

            # Vertical seperator
            self.CONSOLE.print("")

        # Report completion
        self.CONSOLE.log(
            f"Encryption completed: {len(type_buffer.keys())} targets encrypted."
        )

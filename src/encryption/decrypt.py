from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from typing import Union, Optional

import os
import base64
import tarfile

from .crypto import CryptoEngine


class Decryptor(CryptoEngine):
    def __init__(self) -> None:
        super().__init__()

    def decrypt_targets(
        self,
        output_folder: str,
        iterations: Union[int, float],
        salt: Optional[Union[int, float, str]] = None,
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
        password = bytes(
            bytes(
                self.CONSOLE.input(prompt="Enter password: ", password=True),
                encoding="utf-8",
            )
        )

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
        if not iterations < int(1e5):
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA512(),
                length=32,
                iterations=iterations,
                salt=salt,
                backend=default_backend(),
            )
        else:
            self.CONSOLE.log(
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
                self.CONSOLE.log(f"Decrypting directory: '{target}'...")
                isdir = True
            else:
                self.CONSOLE.log(f"Decrypting file: '{target}'...")
                isdir = False

            # Open encrypted target file
            with open(target, "rb") as f:
                encrypted = f.read()

            # Decrypt encrypted file
            decrypted = fernet.decrypt(encrypted)

            # Write decrypted output
            target_name = os.path.splitext(os.path.split(target)[-1])[0]

            os.makedirs(output_folder, exist_ok=True)

            with open(os.path.join(output_folder, target_name), "wb") as f:
                f.write(decrypted)

            if isdir:

                self.CONSOLE.log("Extracting directory...")

                # Extract the compressed target
                tar = tarfile.open(
                    os.path.join(output_folder, f"{target_name}"), "r:gz"
                )
                tar.extractall(output_folder)
                tar.close()

                # Delete compressed decrypted file
                os.unlink(os.path.join(output_folder, f"{target_name}"))

            # Vertical seperator
            self.CONSOLE.print("")

        # Report completion
        self.CONSOLE.log(
            f"Decryption completed: {len(path_buffer)} targets decrypted."
        )

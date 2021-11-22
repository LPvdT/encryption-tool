import click

from typing import Union, Optional

from src.encryption.decrypt import Decryptor
from src.encryption.encrypt import Encryptor


@click.group()
@click.option(
    "--output_folder",
    "-o",
    help="Output folder for encrypted/decrypted items.",
    default="./",
)
@click.option(
    "--iterations",
    "-i",
    help="Amount of iterations of the hashing algorithm.",
    default=int(1e5),
)
@click.option(
    "--salt", "-s", help="Custom value for the hashing salt.", default=None
)
@click.pass_context
def main(
    ctx,
    output_folder: str,
    iterations: Union[int, float],
    salt: Optional[Union[int, float, str]] = None,
):
    """
    Simple tool to encrypt or decrypt your files and folders using the SHA-2 algorithm with 512-bit hashing.
    """

    # Add properties to context object
    ctx.obj["output_folder"] = output_folder
    ctx.obj["iterations"] = iterations
    ctx.obj["salt"] = salt


@main.command()
@click.option(
    "--save_key",
    "-S",
    help="Save the encryption key to disk.",
    default=False,
    is_flag=True,
)
@click.argument("targets", nargs=-1)
@click.pass_context
def encrypt(ctx, save_key: bool = False, **kwargs):
    """
    Encrypt file(s), or folder(s).
    """

    # Class object instance
    encryptor = Encryptor()

    # Add property to context object
    ctx.obj["save_key"] = save_key

    # Handlers for direct and indirect encryption targets
    encrypt_params = {
        "output_folder": ctx.obj["output_folder"],
        "iterations": ctx.obj["iterations"],
        "salt": ctx.obj["salt"],
        "save_key": ctx.obj["save_key"],
    }

    if len(kwargs["targets"]) > 0:
        encrypt_params.update(targets=kwargs["targets"])
        encryptor.encrypt_targets(**encrypt_params)
    else:
        encryptor.encrypt_targets(**encrypt_params)


@main.command()
@click.argument("targets", nargs=-1)
@click.pass_context
def decrypt(ctx, **kwargs):
    """
    Decrypt file(s), or folder(s).
    """

    # Class object instance
    decryptor = Decryptor()

    # Handlers for direct and indirect encryption targets
    decrypt_params = {
        "output_folder": ctx.obj["output_folder"],
        "iterations": ctx.obj["iterations"],
        "salt": ctx.obj["salt"],
    }

    if len(kwargs["targets"]) > 0:
        decrypt_params.update(targets=kwargs["targets"])
        decryptor.decrypt_targets(**decrypt_params)
    else:
        decryptor.decrypt_targets(**decrypt_params)


# Entrypoint and context object
def start():
    main(obj={})


if __name__ == "__main__":
    start()

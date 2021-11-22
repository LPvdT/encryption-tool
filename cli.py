import click

from typing import Union, Optional

from src.encryption.crypto import CryptoEngine
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
    ctx.obj["console"] = CryptoEngine().CONSOLE
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

    encryptor = Encryptor()

    ctx.obj["save_key"] = save_key

    if len(kwargs["targets"]) > 0:
        encryptor.encrypt_targets(
            output_folder=ctx.obj["output_folder"],
            iterations=ctx.obj["iterations"],
            salt=ctx.obj["salt"],
            save_key=ctx.obj["save_key"],
            targets=kwargs["targets"],
        )
    else:
        encryptor.encrypt_targets(
            output_folder=ctx.obj["output_folder"],
            iterations=ctx.obj["iterations"],
            salt=ctx.obj["salt"],
            save_key=ctx.obj["save_key"],
        )


@main.command()
@click.argument("targets", nargs=-1)
@click.pass_context
def decrypt(ctx, **kwargs):

    decryptor = Decryptor()

    if len(kwargs["targets"]) > 0:
        decryptor.decrypt_targets(
            output_folder=ctx.obj["output_folder"],
            iterations=ctx.obj["iterations"],
            salt=ctx.obj["salt"],
            targets=kwargs["targets"],
        )
    else:
        decryptor.decrypt_targets(
            output_folder=ctx.obj["output_folder"],
            iterations=ctx.obj["iterations"],
            salt=ctx.obj["salt"],
        )


def start():
    main(obj={})


if __name__ == "__main__":
    start()

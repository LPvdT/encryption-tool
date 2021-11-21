import click


@click.group()
# Ctx opts/args here
@click.pass_context
def main(ctx):
    pass


@main.command()
@click.pass_context
def encrypt(ctx):
    pass


@main.command()
@click.pass_context
def decrypt(ctx):
    pass


def start():
    main(obj=dict)


if __name__ == "__main__":
    start()

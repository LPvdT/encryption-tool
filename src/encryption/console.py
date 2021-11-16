from rich.console import Console
from rich.traceback import install


class CryptoConsole(object):
    def __init__(self) -> None:
        super().__init__()
        self.CONSOLE = Console()
        install(console=self.CONSOLE)

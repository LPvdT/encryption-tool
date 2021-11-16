from rich.console import Console
from rich.traceback import install


class CryptoConsole(object):
    def __init__(self) -> None:
        super().__init__()

        # Define instance
        self.CONSOLE = Console()

        # Init rich tracebacks
        install(console=self.CONSOLE)

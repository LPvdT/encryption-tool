from __future__ import annotations

import time
from pathlib import Path

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Input, Label, Select, Static, TextArea

from encryption_tool.crypto import decrypt_data, encrypt_data
from encryption_tool.streaming import (
    decrypt_directory,
    decrypt_file,
    encrypt_directory,
    encrypt_file,
)
from encryption_tool.utilities import generate_passphrase, hash_file


THEME = """
Screen { background: #0b1120; color: #e2e8f0; }
#shell { width: 100%; height: 1fr; padding: 1 2; }
.panel { background: #111c2d; border: round #26364a; padding: 1 2; height: auto; }
.title { color: #38bdf8; text-style: bold; text-align: center; padding: 1 0; }
.subtle { color: #94a3b8; }
Label { color: #cbd5e1; margin-top: 1; }
Input, Select, TextArea { background: #0b1120; border: round #334155; color: #e2e8f0; margin-bottom: 1; }
TextArea { height: 7; }
Button { width: 1fr; margin: 1 1 0 0; }
Button.primary { background: #0369a1; color: white; }
Button.success { background: #047857; color: white; }
Button.muted { background: #334155; color: white; }
#actions { height: auto; }
#result { height: auto; min-height: 3; border: round #26364a; padding: 1; margin-top: 1; }
"""


class Dashboard(Screen[None]):
    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="shell"):
            yield Static("CRYPT  /  TERMINAL SECURITY TOOLKIT", classes="title")
            yield Static(
                "Authenticated encryption • file protection • integrity utilities",
                classes="subtle",
            )
            with Vertical(classes="panel"):
                yield Label("WORKSPACES")
                with Horizontal(id="actions"):
                    yield Button("Encrypt", id="go-encrypt", classes="primary")
                    yield Button("Decrypt", id="go-decrypt", classes="success")
                    yield Button("File tools", id="go-files", classes="muted")
                with Horizontal(id="actions"):
                    yield Button("Hash & password", id="go-utils", classes="muted")
                    yield Button("Quit", id="quit", classes="muted")
                yield Static(
                    "AES-256-GCM / ChaCha20-Poly1305  •  Argon2id  •  ETK2 / ETFS",
                    classes="subtle",
                )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        screens = {
            "go-encrypt": EncryptScreen,
            "go-decrypt": DecryptScreen,
            "go-files": FileScreen,
            "go-utils": UtilityScreen,
        }
        if event.button.id in screens:
            self.app.push_screen(screens[event.button.id]())
        elif event.button.id == "quit":
            self.app.exit()


class BaseScreen(Screen[None]):
    CSS = THEME
    heading = "WORKSPACE"

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="shell"):
            with Vertical(classes="panel"):
                yield Static(self.heading, classes="title")
                yield from self.fields()
                yield Static("Ready.", id="result")
                with Horizontal(id="actions"):
                    yield Button("Run", id="run", classes="primary")
                    yield Button("Back", id="back", classes="muted")
        yield Footer()

    def fields(self) -> ComposeResult:
        yield Static("No fields configured.")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "back":
            self.app.pop_screen()
        elif event.button.id == "run":
            self.start_operation()

    def start_operation(self) -> None:
        raise NotImplementedError

    def result(self, message: str) -> None:
        self.query_one("#result", Static).update(message)


class EncryptScreen(BaseScreen):
    heading = "ENCRYPT TEXT"

    def fields(self) -> ComposeResult:
        yield Label("Algorithm")
        yield Select(
            [("AES-256-GCM", "AES-256-GCM"), ("ChaCha20-Poly1305", "ChaCha20-Poly1305")],
            value="AES-256-GCM",
            id="algorithm",
        )
        yield Label("Plaintext")
        yield TextArea(id="plain")
        yield Label("Password")
        yield Input(password=True, placeholder="Use a strong passphrase", id="password")
        yield Label("Optional output file (leave blank for hex)")
        yield Input(placeholder="output.etk", id="destination")

    def start_operation(self) -> None:
        plaintext = self.query_one("#plain", TextArea).text
        password = self.query_one("#password", Input).value
        algorithm = self.query_one("#algorithm", Select).value
        destination = self.query_one("#destination", Input).value.strip()
        self.encrypt_text(plaintext, password, str(algorithm), destination)

    @work(thread=True, exclusive=True)
    def encrypt_text(self, plaintext: str, password: str, algorithm: str, destination: str) -> None:
        try:
            raw = plaintext.encode("utf-8")
            encrypted = encrypt_data(raw, password, algorithm)  # type: ignore[arg-type]
            if destination:
                path = _write_atomic(Path(destination), encrypted)
                message = f"Encrypted {len(raw):,} bytes → {path}"
            else:
                message = f"Encrypted {len(raw):,} bytes. Hex preview: {encrypted[:48].hex()}…"
            self.app.call_from_thread(self.result, message)
        except Exception:
            self.app.call_from_thread(
                self.result, "Encryption failed. Check the inputs and output path."
            )


class DecryptScreen(BaseScreen):
    heading = "DECRYPT TEXT"

    def fields(self) -> ComposeResult:
        yield Label("Encrypted input file (optional)")
        yield Input(placeholder="payload.etk", id="source")
        yield Label("Ciphertext hex (if no file selected)")
        yield TextArea(id="ciphertext")
        yield Label("Password")
        yield Input(password=True, id="password")

    def start_operation(self) -> None:
        source = self.query_one("#source", Input).value.strip()
        ciphertext = self.query_one("#ciphertext", TextArea).text
        password = self.query_one("#password", Input).value
        self.decrypt_text(source, ciphertext, password)

    @work(thread=True, exclusive=True)
    def decrypt_text(self, source: str, ciphertext: str, password: str) -> None:
        try:
            data = Path(source).read_bytes() if source else bytes.fromhex(ciphertext.strip())
            plaintext = decrypt_data(data, password)
            try:
                rendered = plaintext.decode("utf-8")
                message = f"Authenticated successfully. Plaintext: {rendered[:500]}"
            except UnicodeDecodeError:
                message = (
                    f"Authenticated binary payload: {len(plaintext):,} bytes. "
                    "Use File tools for binary files."
                )
            self.app.call_from_thread(self.result, message)
        except Exception:
            self.app.call_from_thread(
                self.result,
                "Decryption failed: incorrect password, malformed input, or damaged data.",
            )


class FileScreen(BaseScreen):
    heading = "FILE / DIRECTORY ENCRYPTION"

    def fields(self) -> ComposeResult:
        yield Label("Mode")
        yield Select(
            [
                ("Encrypt file", "encrypt-file"),
                ("Decrypt file", "decrypt-file"),
                ("Encrypt directory", "encrypt-dir"),
                ("Decrypt directory", "decrypt-dir"),
            ],
            value="encrypt-file",
            id="mode",
        )
        yield Label("Source path")
        yield Input(placeholder="/path/to/file-or-directory", id="source")
        yield Label("Destination path")
        yield Input(placeholder="/path/to/output", id="destination")
        yield Label("Password")
        yield Input(password=True, id="password")
        yield Label("Algorithm (encryption only)")
        yield Select(
            [("AES-256-GCM", "AES-256-GCM"), ("ChaCha20-Poly1305", "ChaCha20-Poly1305")],
            value="AES-256-GCM",
            id="algorithm",
        )

    def start_operation(self) -> None:
        mode = str(self.query_one("#mode", Select).value)
        source = self.query_one("#source", Input).value.strip()
        destination = self.query_one("#destination", Input).value.strip()
        password = self.query_one("#password", Input).value
        algorithm = str(self.query_one("#algorithm", Select).value)
        self.process_files(mode, source, destination, password, algorithm)

    @work(thread=True, exclusive=True)
    def process_files(
        self, mode: str, source_value: str, destination_value: str,
        password: str, algorithm: str
    ) -> None:
        try:
            source, destination = Path(source_value), Path(destination_value)
            started = time.perf_counter()
            if mode == "encrypt-file":
                encrypt_file(source, destination, password, algorithm)  # type: ignore[arg-type]
                count = 1
            elif mode == "decrypt-file":
                decrypt_file(source, destination, password)
                count = 1
            elif mode == "encrypt-dir":
                count = len(encrypt_directory(source, destination, password, algorithm))  # type: ignore[arg-type]
            elif mode == "decrypt-dir":
                count = len(decrypt_directory(source, destination, password))
            else:
                raise ValueError("Unknown file operation.")
            elapsed = time.perf_counter() - started
            self.app.call_from_thread(
                self.result,
                f"Completed {count} file(s) in {elapsed:.2f}s. Output: {destination}",
            )
        except Exception as exc:
            self.app.call_from_thread(
                self.result, f"Operation failed: {type(exc).__name__}: {exc}"
            )


class UtilityScreen(BaseScreen):
    heading = "INTEGRITY & PASSWORD UTILITIES"

    def fields(self) -> ComposeResult:
        yield Label("Action")
        yield Select(
            [("SHA-256 file digest", "hash"), ("Generate secure password", "password")],
            value="hash",
            id="action",
        )
        yield Label("File path (hash action)")
        yield Input(placeholder="/path/to/file", id="source")
        yield Label("Password length (8–256)")
        yield Input(value="32", id="length")

    def start_operation(self) -> None:
        action = str(self.query_one("#action", Select).value)
        source = self.query_one("#source", Input).value.strip()
        length = self.query_one("#length", Input).value
        self.run_utility(action, source, length)

    @work(thread=True, exclusive=True)
    def run_utility(self, action: str, source: str, length: str) -> None:
        try:
            if action == "hash":
                message = f"SHA-256: {hash_file(source)}"
            elif action == "password":
                message = f"Generated password (copy it now): {generate_passphrase(int(length))}"
            else:
                raise ValueError("Unknown utility.")
            self.app.call_from_thread(self.result, message)
        except Exception as exc:
            self.app.call_from_thread(
                self.result, f"Utility failed: {type(exc).__name__}: {exc}"
            )


def _write_atomic(destination: Path, data: bytes) -> Path:
    import os
    import tempfile

    if destination.exists():
        raise FileExistsError(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        dir=destination.parent, prefix=f".{destination.name}.", delete=False
    ) as handle:
        temporary = Path(handle.name)
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    try:
        os.link(temporary, destination)
        temporary.unlink()
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return destination


class EncryptionApp(App[None]):
    TITLE = "CRYPT | Terminal Security Toolkit"
    CSS = THEME
    BINDINGS = [("ctrl+q", "quit", "Quit")]

    def on_mount(self) -> None:
        self.push_screen(Dashboard())


def main() -> None:
    EncryptionApp().run()


if __name__ == "__main__":
    main()

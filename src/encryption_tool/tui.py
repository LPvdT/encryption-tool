from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)

from encryption_tool.crypto import AlgorithmType, decrypt_data, encrypt_data


class MainMenuScreen(Screen[None]):
    """Main menu screen to choose between encryption and decryption."""

    CSS = """
    MainMenuScreen {
        align: center middle;
        background: #0f172a;
    }

    #menu-container {
        width: 50;
        height: auto;
        background: #1e293b;
        border: solid #334155;
        border-title-color: #38bdf8;
        border-title-style: bold;
        padding: 2 4;
    }

    .menu-title {
        color: #38bdf8;
        text-style: bold;
        text-align: center;
        margin-bottom: 2;
    }

    Button {
        width: 100%;
        margin-top: 1;
        margin-bottom: 1;
        text-style: bold;
    }

    #btn-goto-encrypt {
        background: #0284c7;
        color: #f8fafc;
    }
    #btn-goto-encrypt:hover {
        background: #0ea5e9;
    }

    #btn-goto-decrypt {
        background: #16a34a;
        color: #f8fafc;
    }
    #btn-goto-decrypt:hover {
        background: #22c55e;
    }

    #btn-exit {
        background: #475569;
        color: #f8fafc;
    }
    #btn-exit:hover {
        background: #64748b;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="menu-container") as container:
            container.border_title = "🔒 SECURE TOOLKIT"
            yield Static("Select an Operation Mode", classes="menu-title")
            yield Button("🔐 Encrypt Payload / File", id="btn-goto-encrypt")
            yield Button("🔓 Decrypt Payload / File", id="btn-goto-decrypt")
            yield Button("Exit", id="btn-exit")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-goto-encrypt":
            self.app.push_screen(EncryptScreen())
        elif event.button.id == "btn-goto-decrypt":
            self.app.push_screen(DecryptScreen())
        elif event.button.id == "btn-exit":
            self.app.exit()


class EncryptScreen(Screen[None]):
    """Dedicated workspace for encrypting text or files."""

    CSS = """
    EncryptScreen {
        background: #0f172a;
        color: #f8fafc;
    }
    VerticalScroll {
        padding: 1 3;
    }
    .panel {
        background: #1e293b;
        border: solid #334155;
        border-title-color: #38bdf8;
        border-title-style: bold;
        padding: 1 2;
        margin-bottom: 1;
    }
    Label {
        color: #cbd5e1;
        margin-top: 1;
        text-style: bold;
    }
    .input-box, Select {
        background: #0f172a;
        border: solid #475569;
        color: #f8fafc;
        margin-bottom: 1;
    }
    Button {
        margin-top: 1;
        width: 100%;
        text-style: bold;
    }
    #btn-encrypt {
        background: #0284c7;
        color: #f8fafc;
    }
    #btn-back {
        background: #475569;
        color: #f8fafc;
    }
    TextArea {
        height: 5;
        background: #0f172a;
        border: solid #475569;
        color: #38bdf8;
        margin-top: 1;
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(), Vertical(classes="panel") as v:
            v.border_title = "🔐 ENCRYPTION WORKSPACE"
            yield Label("Algorithm Selection:")
            yield Select[AlgorithmType](
                [
                    ("AES-256-GCM (Hardware Accelerated)", "AES-256-GCM"),
                    ("ChaCha20-Poly1305 (Stream Cipher)", "ChaCha20-Poly1305"),
                ],
                value="AES-256-GCM",
                id="encrypt-algo",
            )
            yield Label("Secret Text / Payload:")
            yield TextArea(id="encrypt-input")
            yield Label("Encryption Password:")
            yield Input(
                placeholder="Enter strong password...",
                password=True,
                id="encrypt-pass",
                classes="input-box",
            )
            yield Label("Save to File Path (Optional - e.g., secret.enc):")
            yield Input(
                placeholder="Leave blank for Hex output only...",
                id="encrypt-file",
                classes="input-box",
            )
            yield Button("Encrypt Payload", id="btn-encrypt")
            yield Label("Output / Ciphertext (Hex or File Status):")
            yield TextArea(id="encrypt-output", read_only=True)
            yield Button("← Back to Main Menu", id="btn-back")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-encrypt":
            text_area = self.query_one("#encrypt-input", TextArea)
            pass_input = self.query_one("#encrypt-pass", Input)
            file_input = self.query_one("#encrypt-file", Input)
            algo_select = self.query_one("#encrypt-algo", Select)
            out_area = self.query_one("#encrypt-output", TextArea)

            try:
                raw_bytes = text_area.text.encode("utf-8")
                algo = (
                    str(algo_select.value)
                    if algo_select.value is not Select.BLANK
                    else "AES-256-GCM"
                )

                encrypted = encrypt_data(raw_bytes, pass_input.value, algorithm=algo)  # type: ignore[arg-type]

                target_file = file_input.value.strip()
                if target_file:
                    Path(target_file).write_bytes(encrypted)
                    out_area.text = f"✔ Success! Written to: {target_file}\n\nHex:\n{encrypted.hex()}"  # ruff: ignore[line-too-long]
                else:
                    out_area.text = encrypted.hex()
            except Exception as e:
                out_area.text = f"❌ Error: {e}"

        elif event.button.id == "btn-back":
            self.app.pop_screen()


class DecryptScreen(Screen[None]):
    """Dedicated workspace for decrypting text or files."""

    CSS = """
    DecryptScreen {
        background: #0f172a;
        color: #f8fafc;
    }
    VerticalScroll {
        padding: 1 3;
    }
    .panel {
        background: #1e293b;
        border: solid #334155;
        border-title-color: #38bdf8;
        border-title-style: bold;
        padding: 1 2;
        margin-bottom: 1;
    }
    Label {
        color: #cbd5e1;
        margin-top: 1;
        text-style: bold;
    }
    .input-box {
        background: #0f172a;
        border: solid #475569;
        color: #f8fafc;
        margin-bottom: 1;
    }
    Button {
        margin-top: 1;
        width: 100%;
        text-style: bold;
    }
    #btn-decrypt {
        background: #16a34a;
        color: #f8fafc;
    }
    #btn-back {
        background: #475569;
        color: #f8fafc;
    }
    TextArea {
        height: 5;
        background: #0f172a;
        border: solid #475569;
        color: #38bdf8;
        margin-top: 1;
        margin-bottom: 1;
    }
    """

    def compose(self) -> ComposeResult:
        with VerticalScroll(), Vertical(classes="panel") as v:
            v.border_title = "🔓 DECRYPTION WORKSPACE"
            yield Label("Load from Encrypted File Path (Optional):")
            yield Input(
                placeholder="Path to .enc file or leave blank to paste hex...",
                id="decrypt-file",
                classes="input-box",
            )
            yield Label("Ciphertext (Hex):")
            yield TextArea(id="decrypt-input")
            yield Label("Decryption Password:")
            yield Input(
                placeholder="Enter password...",
                password=True,
                id="decrypt-pass",
                classes="input-box",
            )
            yield Button("Decrypt Payload", id="btn-decrypt")
            yield Label("Recovered Plaintext:")
            yield TextArea(id="decrypt-output", read_only=True)
            yield Button("← Back to Main Menu", id="btn-back")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-decrypt":
            text_area = self.query_one("#decrypt-input", TextArea)
            pass_input = self.query_one("#decrypt-pass", Input)
            file_input = self.query_one("#decrypt-file", Input)
            out_area = self.query_one("#decrypt-output", TextArea)

            try:
                target_file = file_input.value.strip()
                if target_file:
                    encrypted_bytes = Path(target_file).read_bytes()
                else:
                    encrypted_bytes = bytes.fromhex(text_area.text.strip())

                decrypted = decrypt_data(encrypted_bytes, pass_input.value)
                out_area.text = decrypted.decode("utf-8")
            except Exception as e:
                out_area.text = f"❌ Decryption failed: {e}"

        elif event.button.id == "btn-back":
            self.app.pop_screen()


class EncryptionApp(App[None]):
    """Modern multi-screen TUI for secure encryption and decryption."""

    TITLE = "🔒 Secure Encryption Toolkit v2.0"

    def on_mount(self) -> None:
        self.push_screen(MainMenuScreen())


def main() -> None:
    app = EncryptionApp()
    app.run()


if __name__ == "__main__":
    main()

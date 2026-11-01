from __future__ import annotations

from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Label, Static, TextArea

from encryption_tool.crypto import decrypt_data, encrypt_data


class EncryptionApp(App[None]):
    """Modern TUI for secure encryption and decryption."""

    CSS = """
    Screen {
        background: $surface;
    }
    VerticalScroll {
        padding: 1 2;
    }
    .section-title {
        color: $accent;
        text-style: bold;
        margin-top: 1;
        margin-bottom: 1;
    }
    .input-box {
        margin-bottom: 1;
    }
    Button {
        margin-top: 1;
        margin-bottom: 2;
        width: 100%;
    }
    TextArea {
        height: 8;
        margin-bottom: 1;
    }
    """

    TITLE = "🔒 Secure Encryption Toolkit"

    def compose(self) -> ComposeResult:
        yield Header()
        yield Footer()
        with VerticalScroll():
            # Encrypt Section
            yield Static("--- ENCRYPT ---", classes="section-title")
            yield Label("Secret Text / Payload:")
            yield TextArea(id="encrypt-input")
            yield Label("Encryption Password:")
            yield Input(
                placeholder="Enter strong password...",
                password=True,
                id="encrypt-pass",
                classes="input-box",
            )
            yield Button("Encrypt Payload", variant="primary", id="btn-encrypt")
            yield Label("Result / Ciphertext (Hex):")
            yield TextArea(id="encrypt-output", read_only=True)

            # Decrypt Section
            yield Static("--- DECRYPT ---", classes="section-title")
            yield Label("Ciphertext (Hex):")
            yield TextArea(id="decrypt-input")
            yield Label("Decryption Password:")
            yield Input(
                placeholder="Enter password...",
                password=True,
                id="decrypt-pass",
                classes="input-box",
            )
            yield Button("Decrypt Payload", variant="success", id="btn-decrypt")
            yield Label("Recovered Plaintext:")
            yield TextArea(id="decrypt-output", read_only=True)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-encrypt":
            text_area = self.query_one("#encrypt-input", TextArea)
            pass_input = self.query_one("#encrypt-pass", Input)
            out_area = self.query_one("#encrypt-output", TextArea)

            try:
                raw_bytes = text_area.text.encode("utf-8")
                encrypted = encrypt_data(raw_bytes, pass_input.value)
                out_area.text = encrypted.hex()
            except Exception as e:
                out_area.text = f"Error: {e}"

        elif event.button.id == "btn-decrypt":
            text_area = self.query_one("#decrypt-input", TextArea)
            pass_input = self.query_one("#decrypt-pass", Input)
            out_area = self.query_one("#decrypt-output", TextArea)

            try:
                encrypted_bytes = bytes.fromhex(text_area.text.strip())
                decrypted = decrypt_data(encrypted_bytes, pass_input.value)
                out_area.text = decrypted.decode("utf-8")
            except Exception as e:
                out_area.text = f"Decryption failed: {e}"


def main() -> None:
    app = EncryptionApp()
    app.run()


if __name__ == "__main__":
    main()

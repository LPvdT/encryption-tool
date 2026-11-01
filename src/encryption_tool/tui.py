from __future__ import annotations

from pathlib import Path

from textual.app import App, ComposeResult
from textual.containers import VerticalScroll
from textual.widgets import (
    Button,
    Footer,
    Header,
    Input,
    Label,
    Select,
    Static,
    TextArea,
)

from encryption_tool.crypto import AlgorithmType, decrypt_data, encrypt_data


class EncryptionApp(App[None]):
    """Modern TUI for secure encryption and decryption with file support."""

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
    Select {
        margin-bottom: 1;
    }
    Button {
        margin-top: 1;
        margin-bottom: 2;
        width: 100%;
    }
    TextArea {
        height: 6;
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
            yield Label("Algorithm:")
            yield Select[AlgorithmType](
                [
                    ("AES-256-GCM", "AES-256-GCM"),
                    ("ChaCha20-Poly1305", "ChaCha20-Poly1305"),
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
                placeholder="Leave blank to output Hex only...",
                id="encrypt-file",
                classes="input-box",
            )
            yield Button("Encrypt Payload", variant="primary", id="btn-encrypt")
            yield Label("Result / Ciphertext (Hex or File Status):")
            yield TextArea(id="encrypt-output", read_only=True)

            # Decrypt Section
            yield Static("--- DECRYPT ---", classes="section-title")
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
            yield Button("Decrypt Payload", variant="success", id="btn-decrypt")
            yield Label("Recovered Plaintext:")
            yield TextArea(id="decrypt-output", read_only=True)

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
                    out_area.text = f"Success! Encrypted data written to: {target_file}\n\nHex:\n{encrypted.hex()}"  # ruff: ignore[line-too-long]
                else:
                    out_area.text = encrypted.hex()
            except Exception as e:
                out_area.text = f"Error: {e}"

        elif event.button.id == "btn-decrypt":
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
                out_area.text = f"Decryption failed: {e}"


def main() -> None:
    app = EncryptionApp()
    app.run()


if __name__ == "__main__":
    main()

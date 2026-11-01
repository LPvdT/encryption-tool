from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any, cast

from textual import work
from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.screen import Screen
from textual.widgets import (
    Button,
    DirectoryTree,
    Footer,
    Header,
    Input,
    Label,
    ProgressBar,
    Select,
    Static,
    TextArea,
)

from encryption_tool.config import AppConfig, config_path, load_config, save_config
from encryption_tool.crypto import AlgorithmType, decrypt_data, encrypt_data
from encryption_tool.history import read_history, record_operation
from encryption_tool.keys import generate_key, inspect_key, load_key
from encryption_tool.streaming import (
    decrypt_directory,
    decrypt_file,
    encrypt_directory,
    encrypt_file,
    inspect_file,
)
from encryption_tool.utilities import (
    HASH_ALGORITHMS,
    generate_passphrase,
    hash_file,
    hmac_bytes,
    verify_hmac,
)

CSS = """
Screen { background: #0b1120; color: #e2e8f0; }
#layout { height: 1fr; }
#sidebar { width: 24; background: #111c2d; border-right: solid #26364a; padding: 1; }
#brand { color: #38bdf8; text-style: bold; padding: 1; }
#content { width: 1fr; padding: 1 2; }
.panel { background: #111c2d; border: round #26364a; padding: 1 2; height: auto; }
.heading { color: #38bdf8; text-style: bold; padding: 1 0; }
.subtle { color: #94a3b8; }
Label { margin-top: 1; color: #cbd5e1; }
Input, Select, TextArea { background: #0b1120; border: round #334155; margin-bottom: 1; }
TextArea { height: 6; }
Button { margin: 1 0; }
#result { border: round #26364a; padding: 1; min-height: 3; }
#progress { margin: 1 0; }
DirectoryTree { height: 14; border: round #334155; margin: 1 0; }
.light-theme { background: #f8fafc; color: #0f172a; }
.light-theme #sidebar { background: #e2e8f0; border-right: solid #cbd5e1; }
.light-theme #content { background: #f8fafc; }
.light-theme Input, .light-theme Select, .light-theme TextArea {
    background: #ffffff;
    color: #0f172a;
    border: round #94a3b8;
}
.light-theme #result { border: round #cbd5e1; }
"""


class Workspace(Screen[None]):
    CSS = CSS

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="layout"):
            with Vertical(id="sidebar"):
                yield Static("CRYPT / 2.2", id="brand")
                for label, screen in [
                    ("Dashboard", "dashboard"),
                    ("Encrypt", "encrypt"),
                    ("Decrypt", "decrypt"),
                    ("Files", "files"),
                    ("Keys", "keys"),
                    ("Utilities", "utilities"),
                    ("Inspect", "inspect"),
                    ("History", "history"),
                    ("Settings", "settings"),
                ]:
                    yield Button(label, id=f"nav-{screen}")
            with VerticalScroll(id="content"):
                yield Static("TERMINAL SECURITY TOOLKIT", classes="heading")
                yield Static("Select a workspace from the navigation.", id="workspace")
                yield Static("READY", id="result")
                yield ProgressBar(total=100, show_eta=False, id="progress")
                yield Button("Cancel current operation", id="cancel")
        yield Footer()

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        ident = event.button.id or ""
        app = cast(EncryptionApp, self.app)
        if ident.startswith("nav-"):
            await app.show_workspace(ident[4:])
        elif ident == "cancel":
            app.cancel_operation()


class EncryptionApp(App[None]):
    TITLE = "CRYPT | Terminal Security Toolkit"
    CSS = CSS
    BINDINGS = [
        ("ctrl+q", "quit", "Quit"),
        ("ctrl+1", "go_dashboard", "Dashboard"),
        ("ctrl+e", "go_encrypt", "Encrypt"),
        ("ctrl+shift+d", "go_decrypt", "Decrypt"),
        ("ctrl+h", "go_history", "History"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.config = load_config()
        self.cancel_event = threading.Event()
        self.current_worker = None

    async def on_mount(self) -> None:
        await self.push_screen(Workspace())
        await self.show_workspace("dashboard")
        self._apply_theme()

    def _record_operation(self, *args: Any, **kwargs: Any) -> None:
        record_operation(*args, **kwargs, limit=self.config.history_limit)

    def _set(self, selector: str, value: str) -> None:
        self.screen.query_one(selector, Static).update(value)

    def _update_progress(self, value: int) -> None:
        self.screen.query_one("#progress", ProgressBar).update(progress=value, total=100)

    async def show_workspace(self, name: str) -> None:
        workspace = self.screen
        workspace.remove_class("light-theme")
        if self.config.theme == "light":
            workspace.add_class("light-theme")
        root = workspace.query_one("#workspace", Static)
        await root.remove_children()
        if name == "dashboard":
            await root.mount(
                Static("CRYPT — TERMINAL SECURITY TOOLKIT", classes="heading"),
                Static(
                    "Password-based text encryption and authenticated file protection",
                    classes="subtle",
                ),
                Static("Text payloads: ETK2 · Encrypted files: ETFS"),
                Static("Algorithms: AES-256-GCM and ChaCha20-Poly1305"),
                Static("Password-based key derivation: Argon2id"),
                Static(
                    "ETK3 raw-key payloads are available through the CLI/API, not these TUI panels."
                ),
            )
        elif name == "encrypt":
            await root.mount(
                Static("TEXT ENCRYPTION · ETK2", classes="heading"),
                Label("Plaintext"),
                TextArea(id="text-input"),
                Label("Password"),
                Input(password=True, id="text-password"),
                Label("Algorithm"),
                Select(
                    [("AES-256-GCM", "AES-256-GCM"), ("ChaCha20-Poly1305", "ChaCha20-Poly1305")],
                    value=self.config.default_algorithm, id="text-algorithm",
                ),
                Label("Output file (optional; otherwise ciphertext is shown as hex)"),
                Input(id="text-path"),
                Button("Encrypt", id="run-encrypt"),
            )
        elif name == "decrypt":
            await root.mount(
                Static("DECRYPT · ETK2 TEXT OR ETFS FILE", classes="heading"),
                Label("Encrypted file (ETFS or ETK2)"),
                Input(id="decrypt-file", placeholder="/path/to/encrypted-file.etfs"),
                Label("Browse from current directory; select an encrypted file"),
                DirectoryTree(Path.cwd(), id="decrypt-tree"),
                Label("Or paste ETK2 hexadecimal ciphertext"),
                TextArea(id="decrypt-hex"),
                Label("Password"),
                Input(password=True, id="decrypt-password"),
                Label("Output file (required for ETFS; optional for ETK2)"),
                Input(id="decrypt-output"),
                Button("Decrypt", id="run-decrypt"),
            )
        elif name == "files":
            await root.mount(
                Static("FILE / DIRECTORY / BATCH OPERATIONS", classes="heading"),
                Select(
                    [
                        ("Encrypt file", "encrypt-file"),
                        ("Decrypt file", "decrypt-file"),
                        ("Encrypt directory", "encrypt-dir"),
                        ("Decrypt directory", "decrypt-dir"),
                        ("Batch encrypt files in source directory", "batch-encrypt"),
                        ("Batch decrypt files in source directory", "batch-decrypt"),
                    ],
                    value="encrypt-file",
                    id="file-mode",
                ),
                Label("Source file or directory"),
                Input(id="file-source"),
                Label("Destination file or directory"),
                Input(id="file-destination"),
                Label("Password"),
                Input(password=True, id="file-password"),
                Label("Algorithm"),
                Select(
                    [("AES-256-GCM", "AES-256-GCM"), ("ChaCha20-Poly1305", "ChaCha20-Poly1305")],
                    value=self.config.default_algorithm,
                    id="file-algorithm",
                ),
                Button("Start", id="run-files"),
            )
        elif name == "keys":
            await root.mount(
                Static("KEY MANAGEMENT", classes="heading"),
                Label("Key file path"),
                Input(id="key-path", placeholder="~/.config/encryption-tool/keys/my-key.bin"),
                Button("Generate 256-bit key", id="key-generate"),
                Button("Inspect key fingerprint", id="key-inspect"),
                Static(
                    "Raw keys are stored as 32 random bytes. Protect the file with "
                    "OS permissions/ACLs and backups.",
                    classes="subtle",
                ),
            )
        elif name == "utilities":
            await root.mount(
                Static("HASH / HMAC / PASSWORD", classes="heading"),
                Select(
                    [
                        ("Hash file", "hash"),
                        ("Generate password", "password"),
                        ("HMAC file", "hmac"),
                        ("Verify HMAC", "verify"),
                    ],
                    value="hash",
                    id="util-mode",
                ),
                Label("File path"),
                Input(id="util-path"),
                Label("Key file for HMAC"),
                Input(id="util-key"),
                Label("Expected HMAC (verify only)"),
                Input(id="util-expected"),
                Label("Password length"),
                Input(value="32", id="util-length"),
                Select([(x, x) for x in HASH_ALGORITHMS], value="sha256", id="util-algorithm"),
                Button("Run utility", id="run-utilities"),
            )
        elif name == "inspect":
            await root.mount(
                Static("FILE INSPECTION", classes="heading"),
                Label("Encrypted file"),
                Input(id="inspect-path"),
                Button("Inspect header", id="run-inspect"),
                Static(
                    "Metadata inspection does not authenticate ciphertext; successful "
                    "decryption is required to verify its tag.",
                    classes="subtle",
                ),
            )
        elif name == "history":
            await root.mount(
                Static("RECENT OPERATIONS", classes="heading"),
                Static(
                    "\n".join(
                        f"{r.get('timestamp', '')}  {r.get('operation', '')}  {r.get('status', '')}"
                        for r in read_history(limit=self.config.history_limit)
                    )
                    or "No operations recorded."
                ),
            )
        elif name == "settings":
            await root.mount(
                Static("APPLICATION SETTINGS", classes="heading"),
                Static(f"Configuration file: {config_path()}"),
                Label("Theme"),
                Select(
                    [("Dark", "dark"), ("Light", "light")],
                    value=self.config.theme,
                    id="settings-theme",
                ),
                Label("Default encryption algorithm"),
                Select(
                    [("AES-256-GCM", "AES-256-GCM"), ("ChaCha20-Poly1305", "ChaCha20-Poly1305")],
                    value=self.config.default_algorithm, id="settings-algorithm",
                ),
                Label("File encryption chunk size (bytes; 4,096–16,777,216)"),
                Input(value=str(self.config.chunk_size), id="settings-chunk"),
                Label("History entries to retain (0–10,000)"),
                Input(value=str(self.config.history_limit), id="settings-history"),
                Horizontal(
                    Button("Save settings", id="settings-save"),
                    Button("Reload from disk", id="settings-reload"),
                    Button("Reset defaults", id="settings-reset"),
                ),
                Static("Changes are applied after saving.", classes="subtle"),
            )
        self._set("#result", f"READY · {name.upper()}")
        workspace.query_one("#progress", ProgressBar).update(progress=0, total=100)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        ident = event.button.id or ""
        if ident == "cancel":
            self.cancel_operation()
            return
        if ident == "run-encrypt":
            self._text_operation("encrypt")
            return
        if ident == "run-decrypt":
            self._decrypt_operation()
            return
        if ident == "settings-save":
            self._save_settings()
            return
        if ident == "settings-reload":
            self._reload_settings()
            return
        if ident == "settings-reset":
            self._reset_settings()
            return
        if ident == "run-files":
            self._file_operation()
            return
        if ident == "key-generate":
            try:
                p = Path(self.screen.query_one("#key-path", Input).value).expanduser()
                generate_key(p)
                self._set("#result", f"Key created: {p}")
            except Exception as exc:
                self._set("#result", f"Key operation failed: {exc}")
            return
        if ident == "key-inspect":
            try:
                self._set(
                    "#result",
                    str(
                        inspect_key(
                            Path(self.screen.query_one("#key-path", Input).value).expanduser()
                        )
                    ),
                )
            except Exception as exc:
                self._set("#result", f"Key inspection failed: {exc}")
            return
        if ident == "run-utilities":
            self._utility_operation()
            return
        if ident == "run-inspect":
            try:
                self._set(
                    "#result",
                    str(
                        inspect_file(
                            Path(self.screen.query_one("#inspect-path", Input).value).expanduser()
                        )
                    ),
                )
            except Exception as exc:
                self._set("#result", f"Inspection failed: {exc}")

    def on_directory_tree_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        self.screen.query_one("#decrypt-file", Input).value = str(event.path)

    def _apply_theme(self) -> None:
        if self.screen.is_mounted:
            self.screen.remove_class("light-theme")
            if self.config.theme == "light":
                self.screen.add_class("light-theme")

    def _save_settings(self) -> None:
        try:
            updated = AppConfig(
                theme=str(self.screen.query_one("#settings-theme", Select).value),
                chunk_size=int(self.screen.query_one("#settings-chunk", Input).value),
                default_algorithm=cast(
                    AlgorithmType, self.screen.query_one("#settings-algorithm", Select).value
                ),
                history_limit=int(self.screen.query_one("#settings-history", Input).value),
            )
            save_config(updated)
            self.config = updated
            self._apply_theme()
            self._set("#result", f"Settings saved: {config_path()}")
        except (ValueError, OSError) as exc:
            self._set("#result", f"Settings not saved: {exc}")

    def _reload_settings(self) -> None:
        try:
            self.config = load_config()
            self.screen.query_one("#settings-theme", Select).value = self.config.theme
            self.screen.query_one("#settings-algorithm", Select).value = (
                self.config.default_algorithm
            )
            self.screen.query_one("#settings-chunk", Input).value = str(self.config.chunk_size)
            self.screen.query_one("#settings-history", Input).value = str(self.config.history_limit)
            self._apply_theme()
            self._set("#result", "Settings reloaded from disk.")
        except (ValueError, OSError) as exc:
            self._set("#result", f"Could not reload settings: {exc}")

    def _reset_settings(self) -> None:
        defaults = AppConfig()
        self.screen.query_one("#settings-theme", Select).value = defaults.theme
        self.screen.query_one("#settings-algorithm", Select).value = defaults.default_algorithm
        self.screen.query_one("#settings-chunk", Input).value = str(defaults.chunk_size)
        self.screen.query_one("#settings-history", Input).value = str(defaults.history_limit)
        self._set("#result", "Defaults loaded; save settings to persist them.")

    def _decrypt_operation(self) -> None:
        source_text = self.screen.query_one("#decrypt-file", Input).value.strip()
        password = self.screen.query_one("#decrypt-password", Input).value
        output_text = self.screen.query_one("#decrypt-output", Input).value.strip()
        if source_text:
            source = Path(source_text).expanduser()
            if not source.is_file():
                self._set("#result", f"Encrypted file not found: {source}")
                return
            try:
                with source.open("rb") as stream:
                    magic = stream.read(4)
                if magic == b"ETFS":
                    if not output_text:
                        self._set("#result", "Choose an output file for ETFS decryption.")
                        return
                    self.file_decrypt_worker(str(source), output_text, password)
                    return
                plaintext = decrypt_data(source.read_bytes(), password)
                self._write_or_preview(plaintext, output_text)
            except Exception as exc:
                self._set("#result", f"{type(exc).__name__}: {exc}")
            return
        ciphertext = self.screen.query_one("#decrypt-hex", TextArea).text.strip()
        try:
            self._write_or_preview(decrypt_data(bytes.fromhex(ciphertext), password), output_text)
        except Exception as exc:
            self._set("#result", f"{type(exc).__name__}: {exc}")

    def _write_or_preview(self, plaintext: bytes, output_text: str) -> None:
        if output_text:
            target = Path(output_text).expanduser()
            target.parent.mkdir(parents=True, exist_ok=True)
            with target.open("xb") as stream:
                stream.write(plaintext)
            self._set("#result", f"Authenticated plaintext written to {target}")
        else:
            self._set("#result", f"Authenticated plaintext: {plaintext[:500]!r}")

    @work(thread=True, exclusive=True)
    def file_decrypt_worker(self, source: str, destination: str, password: str) -> None:
        try:
            result = decrypt_file(source, destination, password, cancel=self.cancel_event)
            self.app.call_from_thread(self._set, "#result", f"Decrypted file written to {result}")
            self.app.call_from_thread(
                self._record_operation, "decrypt-file", source, destination, "success"
            )
        except Exception as exc:
            self.app.call_from_thread(self._set, "#result", f"{type(exc).__name__}: {exc}")

    def _text_operation(self, mode: str) -> None:
        text = self.screen.query_one("#text-input", TextArea).text
        password = self.screen.query_one("#text-password", Input).value
        algorithm = cast(AlgorithmType, self.screen.query_one("#text-algorithm", Select).value)
        path = self.screen.query_one("#text-path", Input).value.strip()
        self.text_worker(mode, text, password, algorithm, path)

    @work(thread=True, exclusive=True)
    def text_worker(
        self, mode: str, text: str, password: str, algorithm: AlgorithmType, path: str
    ) -> None:
        try:
            if mode == "encrypt":
                value = encrypt_data(text.encode(), password, algorithm)
                if path:
                    target = Path(path).expanduser()
                    if target.exists():
                        raise FileExistsError(target)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with target.open("xb") as f:
                        f.write(value)
                    message = f"Encrypted to {target}"
                else:
                    message = f"ETK2 hex: {value.hex()[:128]}…"
            else:
                data = Path(path).expanduser().read_bytes() if path else bytes.fromhex(text.strip())
                value = decrypt_data(data, password)
                message = f"Authenticated plaintext: {value[:500]!r}"
            self.app.call_from_thread(self._set, "#result", message)
            self.app.call_from_thread(
                record_operation,
                mode,
                path or "text",
                path,
                "success",
                bytes_processed=len(text.encode()),
            )
        except Exception as exc:
            self.app.call_from_thread(self._set, "#result", f"{type(exc).__name__}: {exc}")

    def _file_operation(self) -> None:
        mode = str(self.screen.query_one("#file-mode", Select).value)
        src = self.screen.query_one("#file-source", Input).value.strip()
        dst = self.screen.query_one("#file-destination", Input).value.strip()
        pwd = self.screen.query_one("#file-password", Input).value
        alg = str(self.screen.query_one("#file-algorithm", Select).value)
        self.cancel_event = threading.Event()
        self.file_worker(mode, src, dst, pwd, alg, self.cancel_event)

    @work(thread=True, exclusive=True)
    def file_worker(
        self, mode: str, src: str, dst: str, pwd: str, alg: str, cancel: threading.Event
    ) -> None:
        start = time.perf_counter()

        def progress(done: int, total: int) -> None:
            pct = int(done * 100 / total) if total else 100
            self.app.call_from_thread(self._update_progress, pct)

        try:
            source = Path(src).expanduser()
            target = Path(dst).expanduser()
            if mode == "encrypt-file":
                result = [
                    encrypt_file(
                        source,
                        target,
                        pwd,
                        alg,
                        chunk_size=self.config.chunk_size,
                        progress=progress,
                        cancel=cancel,
                    )
                ]
            elif mode == "decrypt-file":
                result = [decrypt_file(source, target, pwd, progress=progress, cancel=cancel)]
            elif mode == "encrypt-dir":
                result = encrypt_directory(
                    source, target, pwd, alg, progress=progress, cancel=cancel
                )
            elif mode == "decrypt-dir":
                result = decrypt_directory(source, target, pwd, progress=progress, cancel=cancel)
            elif mode == "batch-encrypt":
                from encryption_tool.batch import batch_encrypt

                batch = batch_encrypt(
                    source.iterdir(), target, pwd, alg, progress=progress, cancel=cancel
                )
                result = list(batch.completed)
                if batch.failed:
                    raise RuntimeError(str(batch.failed))
            else:
                from encryption_tool.batch import batch_decrypt

                batch = batch_decrypt(
                    source.glob("*.etfs"), target, pwd, progress=progress, cancel=cancel
                )
                result = list(batch.completed)
                if batch.failed:
                    raise RuntimeError(str(batch.failed))
            message = f"Completed {len(result)} file(s) in {time.perf_counter() - start:.2f}s"
            self.app.call_from_thread(self._set, "#result", message)
            self.app.call_from_thread(
                record_operation,
                mode,
                src,
                dst,
                "success",
                bytes_processed=sum(p.stat().st_size for p in result),
            )
        except InterruptedError:
            self.app.call_from_thread(
                self._set, "#result", "Cancelled. Temporary output discarded."
            )
        except Exception as exc:
            self.app.call_from_thread(self._set, "#result", f"{type(exc).__name__}: {exc}")

    def cancel_operation(self) -> None:
        self.cancel_event.set()
        self._set("#result", "Cancellation requested…")

    def _utility_operation(self) -> None:
        mode = str(self.screen.query_one("#util-mode", Select).value)
        path = self.screen.query_one("#util-path", Input).value.strip()
        key = self.screen.query_one("#util-key", Input).value.strip()
        expected = self.screen.query_one("#util-expected", Input).value.strip()
        length = self.screen.query_one("#util-length", Input).value
        algorithm = str(self.screen.query_one("#util-algorithm", Select).value)
        self.utility_worker(mode, path, key, expected, length, algorithm)

    @work(thread=True, exclusive=True)
    def utility_worker(
        self, mode: str, path: str, key_path: str, expected: str, length: str, algorithm: str
    ) -> None:
        try:
            if mode == "hash":
                result = f"{algorithm}: {hash_file(Path(path).expanduser(), algorithm)}"
            elif mode == "password":
                result = generate_passphrase(int(length))
            elif mode == "hmac":
                result = hmac_bytes(
                    Path(path).read_bytes(),
                    load_key(Path(key_path).expanduser()),
                    algorithm if algorithm in ("sha256", "sha512") else "sha256",
                )
            else:
                result = str(
                    verify_hmac(
                        Path(path).read_bytes(), load_key(Path(key_path).expanduser()), expected
                    )
                )
            self.app.call_from_thread(self._set, "#result", result)
            self.app.call_from_thread(record_operation, mode, path, "", "success")
        except Exception as exc:
            self.app.call_from_thread(self._set, "#result", f"{type(exc).__name__}: {exc}")

    async def action_go_dashboard(self) -> None:
        await self.show_workspace("dashboard")

    async def action_go_encrypt(self) -> None:
        await self.show_workspace("encrypt")

    async def action_go_decrypt(self) -> None:
        await self.show_workspace("decrypt")

    async def action_go_history(self) -> None:
        await self.show_workspace("history")


def main() -> None:
    EncryptionApp().run()


if __name__ == "__main__":
    main()

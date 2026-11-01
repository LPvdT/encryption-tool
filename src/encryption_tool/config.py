from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True, slots=True)
class AppConfig:
    theme: str = "dark"
    chunk_size: int = 1_048_576
    default_algorithm: str = "AES-256-GCM"
    history_limit: int = 100


def config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
        return base / "encryption-tool" / "config.toml"
    return (
        Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
        / "encryption-tool"
        / "config.toml"
    )


def load_config(path: str | Path | None = None) -> AppConfig:
    target = Path(path) if path else config_path()
    if not target.exists():
        return AppConfig()
    with target.open("rb") as stream:
        data = tomllib.load(stream)
    chunk = data.get("chunk_size", 1_048_576)
    limit = data.get("history_limit", 100)
    algorithm = data.get("default_algorithm", "AES-256-GCM")
    theme = data.get("theme", "dark")
    if not isinstance(chunk, int) or not 4096 <= chunk <= 16 * 1024 * 1024:
        raise ValueError("Invalid config chunk_size.")
    if not isinstance(limit, int) or not 0 <= limit <= 10_000:
        raise ValueError("Invalid config history_limit.")
    if algorithm not in ("AES-256-GCM", "ChaCha20-Poly1305"):
        raise ValueError("Invalid config default_algorithm.")
    if theme not in ("dark", "light"):
        raise ValueError("Invalid config theme.")
    return AppConfig(theme, chunk, algorithm, limit)


def write_default_config(path: str | Path | None = None) -> Path:
    target = Path(path) if path else config_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise FileExistsError(target)
    target.write_text(
        (
            'theme = "dark"\n'
            "chunk_size = 1048576\n"
            'default_algorithm = "AES-256-GCM"\n'
            "history_limit = 100\n"
        ),
        encoding="utf-8",
    )
    if os.name != "nt":
        target.chmod(0o600)
    return target

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from encryption_tool.streaming import decrypt_file, encrypt_file


@dataclass(frozen=True, slots=True)
class BatchResult:
    completed: tuple[Path, ...]
    failed: tuple[tuple[Path, str], ...]
    cancelled: bool


def batch_encrypt(
    files: Iterable[str | Path],
    destination: str | Path,
    password: str,
    algorithm: str = "AES-256-GCM",
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
    cancel: threading.Event | None = None,
) -> BatchResult:
    items = [Path(p) for p in files]
    total = sum(p.stat().st_size for p in items if p.is_file())
    done = 0
    ok = []
    errors = []
    root = Path(destination)
    for src in items:
        if cancel and cancel.is_set():
            return BatchResult(tuple(ok), tuple(errors), True)
        try:

            def update(n: int, _t: int, base: int = done) -> None:
                if progress:
                    progress(base + n, total)

            dst = root / (src.name + ".etfs")
            encrypt_file(
                src, dst, password, algorithm, overwrite=overwrite, progress=update, cancel=cancel
            )
            ok.append(dst)
            done += src.stat().st_size
        except InterruptedError:
            return BatchResult(tuple(ok), tuple(errors), True)
        except (OSError, ValueError) as exc:
            errors.append((src, str(exc)))
    return BatchResult(tuple(ok), tuple(errors), False)


def batch_decrypt(
    files: Iterable[str | Path],
    destination: str | Path,
    password: str,
    overwrite: bool = False,
    progress: Callable[[int, int], None] | None = None,
    cancel: threading.Event | None = None,
) -> BatchResult:
    items = [Path(p) for p in files]
    total = sum(p.stat().st_size for p in items if p.is_file())
    done = 0
    ok = []
    errors = []
    root = Path(destination)
    for src in items:
        if cancel and cancel.is_set():
            return BatchResult(tuple(ok), tuple(errors), True)
        try:

            def update(n: int, _t: int, base: int = done) -> None:
                if progress:
                    progress(base + n, total)

            dst = root / src.name.removesuffix(".etfs")
            decrypt_file(src, dst, password, overwrite=overwrite, progress=update, cancel=cancel)
            ok.append(dst)
            done += src.stat().st_size
        except InterruptedError:
            return BatchResult(tuple(ok), tuple(errors), True)
        except (OSError, ValueError) as exc:
            errors.append((src, str(exc)))
    return BatchResult(tuple(ok), tuple(errors), False)

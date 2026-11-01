from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path


def history_path() -> Path:
    if os.name == "nt":
        return (
            Path(os.environ.get("APPDATA", Path.home() / "AppData/Roaming"))
            / "encryption-tool"
            / "history.json"
        )
    return (
        Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local/state"))
        / "encryption-tool"
        / "history.json"
    )


def record_operation(
    operation: str,
    source: str,
    destination: str,
    status: str,
    *,
    bytes_processed: int = 0,
    duration_seconds: float = 0.0,
    limit: int = 100,
) -> None:
    if limit <= 0:
        return
    path = history_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    records = []
    if path.exists():
        try:
            records = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(records, list):
                records = []
        except (OSError, json.JSONDecodeError):
            records = []
    records.insert(
        0,
        {
            "timestamp": datetime.now(UTC).isoformat(),
            "operation": operation,
            "source": source,
            "destination": destination,
            "status": status,
            "bytes_processed": bytes_processed,
            "duration_seconds": round(duration_seconds, 3),
        },
    )
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(records[:limit], indent=2), encoding="utf-8")
    if os.name != "nt":
        temporary.chmod(0o600)
    os.replace(temporary, path)


def read_history(limit: int = 20) -> list[dict[str, object]]:
    path = history_path()
    if not path.exists():
        return []
    try:
        records = json.loads(path.read_text(encoding="utf-8"))
        return records[:limit] if isinstance(records, list) else []
    except (OSError, json.JSONDecodeError):
        return []

"""Structured run trace: one JSON line per event."""

from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

from agent.audit import utc_now


class TraceWriter:
    """Collects events in memory and, optionally, appends them to a JSONL file."""

    def __init__(self, run_id: str, path: Path | None = None) -> None:
        self.run_id = run_id
        self.path = Path(path) if path else None
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def event(self, event: str, **fields: Any) -> dict[str, Any]:
        entry: dict[str, Any] = {"ts": utc_now(), "run_id": self.run_id, "event": event}
        entry.update({k: v for k, v in fields.items() if v is not None})
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            self.events.append(entry)
            if self.path:
                fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
                try:
                    os.write(fd, line.encode("utf-8"))
                finally:
                    os.close(fd)
        return entry

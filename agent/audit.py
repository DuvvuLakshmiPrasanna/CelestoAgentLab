"""Append-only command audit log: one JSON object per line.

Every command the agent *attempts* is recorded, including commands a hook
blocked. ``execution_target`` is always ``celesto_sandbox``: nothing in this log
ran on the host. ``provider`` says which backend implemented the sandbox, so an
emulated run can never be mistaken for a real Celesto run.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

EXECUTION_TARGET = "celesto_sandbox"
_MAX_COMMAND_CHARS = 2000


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class CommandAudit:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(
        self,
        sandbox_name: str,
        command: str,
        decision: str,
        *,
        provider: str,
        **extra: Any,
    ) -> dict[str, Any]:
        if decision not in ("allow", "block"):
            raise ValueError("decision must be 'allow' or 'block'")
        text = command if command.strip() else "<empty command>"
        if len(text) > _MAX_COMMAND_CHARS:
            text = text[:_MAX_COMMAND_CHARS] + f"...[+{len(command) - _MAX_COMMAND_CHARS} chars]"
        entry: dict[str, Any] = {
            "ts": utc_now(),
            "sandbox_name": sandbox_name,
            "command": text,
            "decision": decision,
            "execution_target": EXECUTION_TARGET,
            "provider": provider,
        }
        entry.update({k: v for k, v in extra.items() if v is not None})
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with self._lock:
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o644)
            try:
                os.write(fd, line.encode("utf-8"))
            finally:
                os.close(fd)
        return entry

    def reset(self) -> None:
        with self._lock:
            self.path.write_text("", encoding="utf-8")

    def read(self) -> list[dict[str, Any]]:
        if not self.path.is_file():
            return []
        return [json.loads(x) for x in self.path.read_text(encoding="utf-8").splitlines() if x]

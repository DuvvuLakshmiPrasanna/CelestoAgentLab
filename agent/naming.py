"""Collision-proof sandbox names: ``sbx-`` plus 10 lowercase hex characters."""

from __future__ import annotations

import re
import secrets
import threading

NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")

_lock = threading.Lock()
_issued: set[str] = set()


def new_sandbox_name() -> str:
    """Return a name never issued before by this process (40 bits of randomness)."""
    with _lock:
        while True:
            name = "sbx-" + secrets.token_hex(5)
            if name not in _issued:
                _issued.add(name)
                return name


def is_valid_name(name: str) -> bool:
    return isinstance(name, str) and NAME_RE.fullmatch(name) is not None


def new_run_id() -> str:
    return "run-" + secrets.token_hex(5)

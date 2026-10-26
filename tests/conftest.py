"""Shared pytest fixtures. Tests that need Linux+root (namespace jail) or Postgres skip cleanly."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from agent.providers.emulated import availability  # noqa: E402

JAIL_OK, JAIL_REASON = availability()
requires_jail = pytest.mark.skipif(not JAIL_OK, reason=f"namespace jail unavailable: {JAIL_REASON}")


def _db_reachable() -> bool:
    try:
        from app import db

        return db.ping()
    except Exception:  # noqa: BLE001
        return False


@pytest.fixture(scope="session")
def database():
    os.environ.setdefault("DATABASE_URL", "postgresql://ledger:ledger@127.0.0.1:5432/ledger")
    if not _db_reachable():
        pytest.skip("no Postgres reachable at DATABASE_URL")
    from app import db

    db.ensure_schema(retries=1, delay_s=0)
    return db


@pytest.fixture()
def jail_env(tmp_path, monkeypatch):
    """Isolated emulator home, log dir and settings for one test."""
    from agent.audit import CommandAudit
    from agent.config import Settings

    monkeypatch.setenv("EMULATE_CELESTO", "1")
    monkeypatch.setenv("EMULATOR_HOME", str(tmp_path / "emu"))
    monkeypatch.setenv("LOGS_DIR", str(tmp_path / "logs"))
    settings = Settings.from_env()
    return settings, CommandAudit(tmp_path / "logs" / "commands.jsonl")

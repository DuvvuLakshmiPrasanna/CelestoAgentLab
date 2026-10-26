"""Postgres access for the run ledger.

The schema is created by ``seeds/01_runs.sql`` on first boot of the ledger
container. ``ensure_schema`` repeats the same idempotent DDL so the API also
works against a Postgres that did not run the seeds (for example a local
developer database); no manual migration step is ever required.
"""

from __future__ import annotations

import os
import re
import time
from datetime import datetime
from typing import Any

import psycopg
from psycopg.rows import dict_row

SANDBOX_NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")
VALID_STATES = ("created", "ready", "running", "succeeded", "failed", "deleted")
EXECUTION_TARGET = "celesto_sandbox"

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS runs (
    run_id           text PRIMARY KEY,
    sandbox_name     text NOT NULL CHECK (sandbox_name ~ '^sbx-[a-z0-9]{8,}$'),
    problem_id       text NOT NULL,
    state            text NOT NULL CHECK (state IN
                         ('created', 'ready', 'running', 'succeeded', 'failed', 'deleted')),
    execution_target text NOT NULL CHECK (execution_target = 'celesto_sandbox'),
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS runs_sandbox_name_idx ON runs (sandbox_name);
INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
VALUES ('run-seeddemo1', 'sbx-seeddemo1', 'seed-problem', 'deleted', 'celesto_sandbox')
ON CONFLICT (run_id) DO NOTHING;
"""

_COLUMNS = "run_id, sandbox_name, problem_id, state, execution_target, created_at, updated_at"


def database_url() -> str:
    return os.environ.get("DATABASE_URL", "postgresql://ledger:ledger@localhost:5432/ledger")


def connect() -> psycopg.Connection:
    return psycopg.connect(
        database_url(), autocommit=True, row_factory=dict_row, connect_timeout=5
    )


def ensure_schema(retries: int = 30, delay_s: float = 1.0) -> None:
    """Create the table and seed row if missing. Retries while Postgres starts."""
    last: Exception | None = None
    for _ in range(max(1, retries)):
        try:
            with connect() as conn:
                conn.execute(SCHEMA_SQL)
            return
        except psycopg.Error as exc:  # database not ready yet
            last = exc
            time.sleep(delay_s)
    assert last is not None
    raise last


def _jsonable(row: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in row.items():
        out[key] = value.isoformat() if isinstance(value, datetime) else value
    return out


def list_runs() -> list[dict[str, Any]]:
    with connect() as conn:
        rows = conn.execute(
            f"SELECT {_COLUMNS} FROM runs ORDER BY created_at, run_id"
        ).fetchall()
    return [_jsonable(r) for r in rows]


def get_run(run_id: str) -> dict[str, Any] | None:
    with connect() as conn:
        row = conn.execute(
            f"SELECT {_COLUMNS} FROM runs WHERE run_id = %s", (run_id,)
        ).fetchone()
    return _jsonable(row) if row else None


def upsert_run(run: dict[str, str]) -> dict[str, Any]:
    """Insert a run row, or advance the state of an existing run_id.

    A run moves through created -> ready -> running -> succeeded/failed ->
    deleted, so the same run_id is posted several times; upserting keeps the
    endpoint idempotent instead of failing with a duplicate-key error.
    """
    with connect() as conn:
        row = conn.execute(
            f"""
            INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target)
            VALUES (%(run_id)s, %(sandbox_name)s, %(problem_id)s, %(state)s, %(execution_target)s)
            ON CONFLICT (run_id) DO UPDATE SET
                sandbox_name = EXCLUDED.sandbox_name,
                problem_id   = EXCLUDED.problem_id,
                state        = EXCLUDED.state,
                execution_target = EXCLUDED.execution_target,
                updated_at   = now()
            RETURNING {_COLUMNS}
            """,
            run,
        ).fetchone()
    assert row is not None
    return _jsonable(row)


def ping() -> bool:
    try:
        with connect() as conn:
            conn.execute("SELECT 1")
        return True
    except psycopg.Error:
        return False

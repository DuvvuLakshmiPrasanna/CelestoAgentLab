"""Ledger API contract. Uses a real Postgres when reachable (skips otherwise)."""

from __future__ import annotations

import uuid

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.validation import ValidationFailure, validate_run

VALID = {"run_id": "r", "sandbox_name": "sbx-abcdef12", "problem_id": "p",
         "state": "created", "execution_target": "celesto_sandbox"}


def body(**over):
    return {**VALID, "run_id": "t-" + uuid.uuid4().hex[:10], **over}


# ---- pure validation: needs no database -------------------------------------
@pytest.mark.parametrize("over,field", [
    ({"execution_target": "host"}, "execution_target"),
    ({"execution_target": ""}, "execution_target"),
    ({"state": "exploded"}, "state"),
    ({"state": "CREATED"}, "state"),
    ({"sandbox_name": "sbx-short"}, "sandbox_name"),
    ({"sandbox_name": "sbx-UPPERCASE1"}, "sandbox_name"),
    ({"sandbox_name": "box-abcdef12"}, "sandbox_name"),
    ({"sandbox_name": "sbx-abcdef12\n"}, "sandbox_name"),
    ({"sandbox_name": 12345678}, "sandbox_name"),
    ({"run_id": ""}, "run_id"),
    ({"run_id": 5}, "run_id"),
    ({"problem_id": "x" * 500}, "problem_id"),
])
def test_validation_rejects(over, field):
    with pytest.raises(ValidationFailure) as exc:
        validate_run({**VALID, **over})
    assert exc.value.field == field


def test_validation_requires_every_field():
    for key in VALID:
        data = {k: v for k, v in VALID.items() if k != key}
        with pytest.raises(ValidationFailure):
            validate_run(data)


def test_validation_accepts_every_state():
    for state in ("created", "ready", "running", "succeeded", "failed", "deleted"):
        assert validate_run({**VALID, "state": state})["state"] == state


def test_health_needs_no_database():
    with TestClient(app) as client:
        r = client.get("/health")
    assert r.status_code == 200 and r.json() == {"status": "ok"}


def test_bad_json_is_400_without_a_database():
    with TestClient(app) as client:
        assert client.post("/api/runs", content="nope", headers={"content-type": "application/json"}).status_code == 400
        assert client.post("/api/runs", json=[1, 2]).status_code == 400
        assert client.post("/api/runs", json=body(execution_target="host")).status_code == 400


# ---- against Postgres -----------------------------------------------------------
def test_seed_row_is_listed(database):
    with TestClient(app) as client:
        r = client.get("/api/runs")
    assert r.status_code == 200 and isinstance(r.json(), list)
    seed = [x for x in r.json() if x["sandbox_name"] == "sbx-seeddemo1"]
    assert len(seed) == 1 and seed[0]["state"] == "deleted" and seed[0]["execution_target"] == "celesto_sandbox"


def test_post_returns_201_and_the_stored_object(database):
    payload = body()
    with TestClient(app) as client:
        r = client.post("/api/runs", json=payload)
        assert r.status_code == 201
        stored = r.json()
        for k, v in payload.items():
            assert stored[k] == v
        assert any(x["run_id"] == payload["run_id"] for x in client.get("/api/runs").json())


def test_post_is_an_idempotent_state_advance(database):
    payload = body(state="created")
    with TestClient(app) as client:
        assert client.post("/api/runs", json=payload).status_code == 201
        assert client.post("/api/runs", json={**payload, "state": "deleted"}).status_code == 201
        rows = [x for x in client.get("/api/runs").json() if x["run_id"] == payload["run_id"]]
    assert len(rows) == 1 and rows[0]["state"] == "deleted"


def test_rejected_rows_are_not_stored(database):
    bad = body(execution_target="host")
    with TestClient(app) as client:
        assert client.post("/api/runs", json=bad).status_code == 400
        assert not any(x["run_id"] == bad["run_id"] for x in client.get("/api/runs").json())


def test_seed_sql_rerun_does_not_duplicate(database):
    from pathlib import Path
    sql = (Path(__file__).resolve().parent.parent / "seeds" / "01_runs.sql").read_text()
    with database.connect() as conn:
        conn.execute(sql)
        conn.execute(sql)
        n = conn.execute("SELECT count(*) AS n FROM runs WHERE sandbox_name = 'sbx-seeddemo1'").fetchone()["n"]
    assert n == 1


def test_database_rejects_a_bad_row_even_if_the_api_were_bypassed(database):
    import psycopg
    with database.connect() as conn, pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO runs (run_id, sandbox_name, problem_id, state, execution_target) "
                     "VALUES ('x-bypass', 'sbx-abcdef12', 'p', 'created', 'host')")


# ---- reports endpoints ----------------------------------------------------------
def test_reports_are_served_and_traversal_is_refused(tmp_path, monkeypatch):
    (tmp_path / "a.json").write_text('{"ok": true}')
    monkeypatch.setenv("REPORTS_DIR", str(tmp_path))
    with TestClient(app) as client:
        assert client.get("/api/reports").json() == {"reports": ["a.json"]}
        assert client.get("/api/reports/a.json").json() == {"ok": True}
        assert client.get("/api/reports/missing.json").status_code == 404
        assert client.get("/api/reports/..%2F..%2Fetc%2Fpasswd").status_code == 404
        assert client.get("/api/reports/%2e%2e/%2e%2e/etc/passwd").status_code == 404


def test_unknown_job_and_unknown_submission():
    with TestClient(app) as client:
        assert client.get("/api/jobs/run-doesnotexist").status_code == 404
        assert client.post("/api/jobs", json={"submission": "../../etc/passwd"}).status_code == 400

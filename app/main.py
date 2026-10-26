"""Run Ledger API: the trusted control plane.

Endpoints
---------
GET  /health              liveness, always {"status": "ok"}
GET  /ready               readiness, checks Postgres
GET  /api/runs            all ledger rows
POST /api/runs            record (or advance) a sandbox run row
GET  /api/reports         list the report files shipped with the repo
GET  /api/reports/{path}  serve one report file (read-only, no path traversal)
GET  /api/audit-log       the command audit log (logs/commands.jsonl)
POST /api/jobs            start a grading job; the API creates the guest via Celesto
GET  /api/jobs/{run_id}   job status

The API never executes a tool on the host. Jobs call the Celesto SDK (or fail
cleanly when no KVM / no cloud key is available) and the reports stay readable
either way.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from app import db
from app.validation import ValidationFailure, validate_run

log = logging.getLogger("ledger")

ROOT = Path(__file__).resolve().parent.parent


def reports_dir() -> Path:
    return Path(os.environ.get("REPORTS_DIR", str(ROOT / "reports"))).resolve()


def logs_dir() -> Path:
    return Path(os.environ.get("LOGS_DIR", str(ROOT / "logs"))).resolve()


def _bootstrap_schema_in_background() -> None:
    """Make sure the table exists without delaying /health.

    Compose already waits for the ledger healthcheck, so this normally
    succeeds on the first try.
    """
    try:
        db.ensure_schema(retries=60, delay_s=1.0)
        log.info("ledger schema ready")
    except Exception as exc:  # pragma: no cover - only when Postgres never comes up
        log.error("could not prepare ledger schema: %s", exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    threading.Thread(target=_bootstrap_schema_in_background, daemon=True).start()
    yield


app = FastAPI(title="Celesto Sandbox Grader - Run Ledger", version="1.0.0", lifespan=lifespan)


def _error(status: int, message: str, **extra: Any) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": message, **extra})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/ready")
def ready() -> JSONResponse:
    if db.ping():
        return JSONResponse({"status": "ready"})
    return JSONResponse({"status": "database_unavailable"}, status_code=503)


@app.get("/api/runs")
def get_runs() -> Any:
    try:
        db.ensure_schema(retries=1, delay_s=0)
        return db.list_runs()
    except Exception as exc:
        log.exception("listing runs failed")
        return _error(503, "ledger database unavailable", detail=str(exc)[:200])


@app.post("/api/runs")
async def post_run(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        return _error(400, "request body must be valid JSON")
    try:
        run = validate_run(payload)
    except ValidationFailure as exc:
        return _error(400, exc.message, field=exc.field)
    try:
        stored = db.upsert_run(run)
    except Exception as exc:
        log.exception("storing run failed")
        return _error(503, "ledger database unavailable", detail=str(exc)[:200])
    return JSONResponse(status_code=201, content=stored)


# --------------------------------------------------------------------- reports
def _safe_report_path(rel: str) -> Path | None:
    base = reports_dir()
    candidate = (base / rel).resolve()
    if candidate == base or base not in candidate.parents:
        return None
    return candidate if candidate.is_file() else None


@app.get("/api/reports")
def list_reports() -> dict[str, Any]:
    base = reports_dir()
    files = (
        sorted(str(p.relative_to(base)) for p in base.rglob("*") if p.is_file())
        if base.is_dir()
        else []
    )
    return {"reports": files}


@app.get("/api/reports/{rel_path:path}")
def get_report(rel_path: str):
    path = _safe_report_path(rel_path)
    if path is None:
        return _error(404, "report not found")
    return FileResponse(path)


@app.get("/api/audit-log")
def audit_log(limit: int = 200) -> Any:
    path = logs_dir() / "commands.jsonl"
    if not path.is_file():
        return _error(404, "no audit log yet")
    limit = max(1, min(limit, 5000))
    lines = path.read_text(encoding="utf-8").splitlines()[-limit:]
    entries = []
    for line in lines:
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


# ------------------------------------------------------------------------ jobs
@app.post("/api/jobs")
async def post_job(request: Request) -> JSONResponse:
    try:
        payload = await request.json()
    except Exception:
        return _error(400, "request body must be valid JSON")
    if not isinstance(payload, dict):
        return _error(400, "request body must be a JSON object")
    try:
        from app import jobs  # imported lazily: keeps /health independent of the agent code

        job = jobs.submit(str(payload.get("submission", "correct_basic")))
    except jobs.JobRejected as exc:
        return _error(400, str(exc))
    except Exception as exc:
        log.exception("could not start job")
        return _error(500, "could not start job", detail=str(exc)[:200])
    return JSONResponse(status_code=202, content=job)


@app.get("/api/jobs/{run_id}")
def get_job(run_id: str) -> JSONResponse:
    from app import jobs

    job = jobs.get(run_id)
    if job is None:
        return _error(404, "unknown job")
    return JSONResponse(job)


@app.get("/", response_class=PlainTextResponse)
def index() -> str:
    return (
        "Celesto Sandbox Grader - run ledger API\n"
        "GET /health  GET /api/runs  POST /api/runs  GET /api/reports  POST /api/jobs\n"
    )

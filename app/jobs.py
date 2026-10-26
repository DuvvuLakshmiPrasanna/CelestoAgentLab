"""POST /api/jobs: run one grading job through the agent harness.

The API process never executes student code. A job asks the configured provider
for a Celesto computer (``CELESTO_PROVIDER`` local|cloud) and everything
happens inside it. If no provider can start (no KVM, no API key, SDK missing)
the job ends in state ``unavailable`` with the exact reason; the API itself stays
healthy and keeps serving the shipped reports.
"""

from __future__ import annotations

import logging
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from agent import fixtures
from agent.config import Settings
from agent.errors import ProviderUnavailable
from agent.factory import build_job
from agent.naming import new_run_id
from agent.pipeline import JobConfig

log = logging.getLogger("jobs")


class JobRejected(ValueError):
    """The request names a submission that does not exist."""


_lock = threading.Lock()
_jobs: dict[str, dict[str, Any]] = {}
_pool: ThreadPoolExecutor | None = None
_MAX_TRACKED = 500


def _executor(settings: Settings) -> ThreadPoolExecutor:
    global _pool
    if _pool is None:
        _pool = ThreadPoolExecutor(max_workers=max(1, settings.max_concurrent_jobs),
                                   thread_name_prefix="job")
    return _pool


def submit(submission: str) -> dict[str, Any]:
    if submission not in fixtures.list_submissions():
        raise JobRejected(f"unknown submission '{submission}'; choose one of {fixtures.list_submissions()}")
    settings = Settings.from_env()
    run_id = new_run_id()
    record: dict[str, Any] = {"run_id": run_id, "submission": submission, "status": "queued"}
    with _lock:
        if len(_jobs) >= _MAX_TRACKED:
            _jobs.pop(next(iter(_jobs)))
        _jobs[run_id] = record
    _executor(settings).submit(_run, run_id, submission, settings)
    return dict(record)


def get(run_id: str) -> dict[str, Any] | None:
    with _lock:
        record = _jobs.get(run_id)
        return dict(record) if record else None


def _update(run_id: str, **fields: Any) -> None:
    with _lock:
        _jobs[run_id].update(fields)


def _run(run_id: str, submission: str, settings: Settings) -> None:
    _update(run_id, status="running")
    try:
        job = build_job(JobConfig(submission=submission, policy=settings.failure_policy,
                                  run_id=run_id), settings)
        result = job.run()
    except ProviderUnavailable as exc:
        _update(run_id, status="unavailable", error=str(exc),
                hint="set CELESTO_PROVIDER/CELESTO_API_KEY, or run the harness with "
                     "EMULATE_CELESTO=1 on a Linux host as root")
        return
    except Exception as exc:  # noqa: BLE001
        log.exception("job %s crashed", run_id)
        _update(run_id, status="error", error=str(exc)[:300])
        return
    _update(run_id, status="succeeded" if result["success"] else "failed", result=result)

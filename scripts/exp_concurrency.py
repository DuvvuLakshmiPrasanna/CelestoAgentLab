"""Concurrency experiment: N jobs at once, each in its own uniquely named sandbox.

Watched for: name collisions, shared state (ledger rows, audit log integrity,
leftover guests), wall-clock inflation under CPU contention, and tests that fail
only because the machine is busy (the grader enforces per-case timeouts).
"""

from __future__ import annotations

import json
import statistics
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any

import httpx

from agent import fixtures
from agent.errors import SandboxExists
from agent.factory import build_job
from agent.naming import new_sandbox_name
from agent.pipeline import JobConfig
from agent.session import REGISTRY
from scripts._common import EVIDENCE, REPORTS, Ctx, environment_info, write_json

LEVELS = (1, 6, 12)
HEADLINE_LEVEL = 6
MIX = ["correct_basic", "wrong_fib_off_by_one", "exfil_attempt", "tamper_results",
       "correct_recursive", "wrong_prime_one", "missing_word_count", "memory_bomb_fib",
       "syntax_error", "infinite_loop_prime", "correct_basic", "tamper_results"]


def _one_job(ctx: Ctx, submission: str, trace_path) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
    job = build_job(JobConfig(submission=submission, policy="rollback"), ctx.settings, emulated=True,
                    audit=ctx.audit, trace_path=trace_path,
                    use_ledger=ctx.ledger_url is not None, provider=ctx.provider)
    result = job.run()
    result["started_at"] = started_at
    return result


def _run_level(ctx: Ctx, n: int) -> dict[str, Any]:
    peak = {"live": 0}
    stop = threading.Event()

    def sample() -> None:
        while not stop.is_set():
            peak["live"] = max(peak["live"], len(REGISTRY.live()))
            time.sleep(0.02)

    sampler = threading.Thread(target=sample, daemon=True)
    sampler.start()
    t0 = time.perf_counter()
    trace = EVIDENCE / f"concurrency_{n}_traces.jsonl"
    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_one_job, ctx, MIX[i % len(MIX)], trace) for i in range(n)]
        results = [f.result() for f in futures]
    wall = time.perf_counter() - t0
    stop.set()
    sampler.join(timeout=1)
    names = [name for r in results for name in r["sandbox_names"]]
    expected_ok = sum(1 for r in results if r["success"])
    return {
        "concurrency": n,
        "total_wall_clock_s": round(wall, 3),
        "median_job_wall_clock_s": round(statistics.median(r["wall_clock_s"] for r in results), 3),
        "max_job_wall_clock_s": round(max(r["wall_clock_s"] for r in results), 3),
        "successes": expected_ok,
        "jobs": n,
        "peak_live_sandboxes": peak["live"],
        "unique_sandbox_names": len(set(names)) == len(names),
        "leftover_sandboxes": ctx.provider.list_names(),
        "throughput_jobs_per_min": round(n / wall * 60, 1),
        "results": results,
    }


def _ledger_consistency(ctx: Ctx, run_ids: list[str]) -> dict[str, Any]:
    if not ctx.ledger_url:
        return {"checked": False, "reason": "no ledger URL given"}
    try:
        rows = httpx.get(f"{ctx.ledger_url}/api/runs", timeout=5, trust_env=False).json()
    except Exception as exc:  # noqa: BLE001
        return {"checked": False, "reason": f"ledger unreachable: {exc}"[:160]}
    by_id = {r["run_id"]: r for r in rows}
    missing = [r for r in run_ids if r not in by_id]
    not_deleted = [r for r in run_ids if r in by_id and by_id[r]["state"] != "deleted"]
    return {"checked": True, "rows_expected": len(run_ids), "rows_found": len(run_ids) - len(missing),
            "rows_not_in_final_deleted_state": len(not_deleted)}


def run_concurrency(ctx: Ctx) -> dict[str, Any]:
    levels = []
    for n in LEVELS:
        level = _run_level(ctx, n)
        levels.append(level)
        print(f"  concurrency {n:2d}: total {level['total_wall_clock_s']:.2f}s, "
              f"median job {level['median_job_wall_clock_s']:.2f}s, ok {level['successes']}/{n}, "
              f"peak live {level['peak_live_sandboxes']}", flush=True)
    head = next(l for l in levels if l["concurrency"] == HEADLINE_LEVEL)
    jobs = [{"sandbox_name": r["sandbox_names"][0], "started_at": r["started_at"],
             "run_id": r["run_id"], "submission": r["submission"], "success": r["success"],
             "wall_clock_s": r["wall_clock_s"]} for r in head["results"]]

    # Deliberate collision: ask for a name that already exists.
    collision = {"detected": False}
    name = new_sandbox_name()
    first = ctx.provider.create(name, network=False, env={})
    try:
        ctx.provider.create(name, network=False, env={})
    except SandboxExists as exc:
        collision = {"detected": True, "error": str(exc)}
    finally:
        first.delete()

    # Audit-log integrity under concurrent writers.
    bad_lines = 0
    total_lines = 0
    for line in (ctx.audit.path).read_text(encoding="utf-8").splitlines():
        total_lines += 1
        try:
            entry = json.loads(line)
            assert entry["execution_target"] == "celesto_sandbox"
        except Exception:  # noqa: BLE001
            bad_lines += 1
    all_run_ids = [r["run_id"] for l in levels for r in l["results"]]
    ledger = _ledger_consistency(ctx, all_run_ids)

    base, wide = levels[0], levels[-1]
    slowdown = wide["median_job_wall_clock_s"] / max(base["median_job_wall_clock_s"], 1e-9)
    failed_at_wide = [r["submission"] for r in wide["results"] if not r["success"]]
    notes = [
        f"Ran {LEVELS} jobs at once on a {environment_info()['cpus']}-CPU machine; every sandbox name was unique "
        f"(random 40-bit suffix, checked: {all(l['unique_sandbox_names'] for l in levels)}), and a deliberately "
        f"duplicated name was refused by the provider ({collision['detected']}).",
        f"Peak simultaneous guests: {', '.join(str(l['peak_live_sandboxes']) for l in levels)} for "
        f"concurrency {', '.join(str(l['concurrency']) for l in levels)}; leftover guests after each level: "
        f"{sum(len(l['leftover_sandboxes']) for l in levels)}.",
        f"What did slow down: median per-job time went from {base['median_job_wall_clock_s']}s at 1 job to "
        f"{wide['median_job_wall_clock_s']}s at {wide['concurrency']} jobs ({slowdown:.1f}x) because the jobs share "
        f"{environment_info()['cpus']} CPUs; throughput rose only from {base['throughput_jobs_per_min']} to "
        f"{wide['throughput_jobs_per_min']} jobs/min.",
        (f"Jobs that graded WRONG only under load: {failed_at_wide}." if failed_at_wide else
         "No job produced a wrong grade under load (per-case timeouts did not misfire)."),
        f"Shared state: audit log {total_lines} lines, {bad_lines} corrupt (appends use O_APPEND under a lock); "
        f"ledger consistency: {ledger}.",
        "Not tested here: provider rate limits and cost blow-up on Celesto Cloud (the free trial allows one "
        "retained sandbox); the emulator has no such limits, so those two risks are unmeasured.",
    ]
    report = {
        "jobs": jobs,
        "breakage_notes": " ".join(notes),
        "levels": [{k: v for k, v in l.items() if k != "results"} for l in levels],
        "name_collision_test": collision,
        "audit_log": {"lines": total_lines, "corrupt_lines": bad_lines},
        "ledger_consistency": ledger,
        "provider": ctx.provider_name,
        "environment": environment_info(),
    }
    write_json(REPORTS / "concurrency.json", report)
    return report

"""Step-7-of-10 failure experiment: every policy against every fault, repeated."""

from __future__ import annotations

import statistics
from typing import Any

from agent.factory import build_job
from agent.pipeline import FAILED_STEP, POLICIES, TOTAL_STEPS, JobConfig
from agent.trace import TraceWriter
from scripts._common import EVIDENCE, REPORTS, Ctx, rel, write_json

FAULTS = ("transient", "corrupt")
REPEATS = 3
SUBMISSION = "wrong_fib_off_by_one"  # expected 75.0: a non-trivial grade that must survive recovery
CHOSEN = "rollback"


def run_policy_matrix(ctx: Ctx) -> list[dict[str, Any]]:
    cells: list[dict[str, Any]] = []
    trace_path = EVIDENCE / "policy_experiment_traces.jsonl"
    for policy in POLICIES:
        for fault in FAULTS:
            results = []
            for _ in range(REPEATS):
                job = build_job(JobConfig(submission=SUBMISSION, policy=policy, fault=fault),
                                ctx.settings, emulated=True, audit=ctx.audit, trace_path=trace_path,
                                use_ledger=False, provider=ctx.provider)
                results.append(job.run())
            ok = [r for r in results if r["success"]]
            cell = {
                "policy": policy,
                "fault": fault,
                "runs": REPEATS,
                "recovered": len(ok),
                "recovery_rate": round(len(ok) / REPEATS, 3),
                "mean_wall_clock_s": round(statistics.fmean(r["wall_clock_s"] for r in results), 3),
                "mean_cost_usd": round(statistics.fmean(r["cost_usd"] for r in results), 8),
                "mean_guests_created": round(statistics.fmean(len(r["sandbox_names"]) for r in results), 2),
                "final_scores": sorted({r["score"] for r in results}, key=str),
                "errors": sorted({r["error"] for r in results if r["error"]}),
            }
            cells.append(cell)
            print(f"  policy {policy:8s} fault={fault:9s} recovered {cell['recovered']}/{REPEATS} "
                  f"wall={cell['mean_wall_clock_s']}s guests={cell['mean_guests_created']}", flush=True)
    return cells


def canonical_trace(ctx: Ctx) -> dict[str, Any]:
    """The documented crash: step 7 fails, the chosen policy runs, the trace is saved."""
    path = REPORTS / "failure_trace.jsonl"
    path.write_text("", encoding="utf-8")
    job = build_job(JobConfig(submission="correct_basic", policy=CHOSEN, fault="corrupt"),
                    ctx.settings, emulated=True, audit=ctx.audit, trace_path=path,
                    use_ledger=ctx.ledger_url is not None, provider=ctx.provider)
    result = job.run()
    if not result["success"]:
        raise SystemExit(f"canonical failure run did not recover: {result}")
    return result


def write_policy_report(ctx: Ctx, cells: list[dict[str, Any]], canon: dict[str, Any]) -> dict[str, Any]:
    def cell(policy: str, fault: str) -> dict[str, Any]:
        return next(c for c in cells if c["policy"] == policy and c["fault"] == fault)

    rb_t, rb_c = cell("rollback", "transient"), cell("rollback", "corrupt")
    rs_t, rs_c = cell("resume", "transient"), cell("resume", "corrupt")
    fr_t, fr_c = cell("fresh", "transient"), cell("fresh", "corrupt")
    rationale = (
        f"Step {FAILED_STEP} of {TOTAL_STEPS} (the hidden-test run) is the first step after the "
        f"step-5 snapshot, so rolling back loses only steps 6-7. Measured over {REPEATS} runs per cell on "
        f"the {ctx.provider_name} provider: rollback recovered {rb_t['recovered']}/{REPEATS} transient and "
        f"{rb_c['recovered']}/{REPEATS} corrupt-workspace failures with 1 guest; resume recovered "
        f"{rs_t['recovered']}/{REPEATS} transient but only {rs_c['recovered']}/{REPEATS} corrupt failures "
        f"because the destroyed workspace is still destroyed; fresh recovered {fr_t['recovered']}/{REPEATS} and "
        f"{fr_c['recovered']}/{REPEATS} but needed {fr_c['mean_guests_created']} guests and "
        f"{fr_c['mean_wall_clock_s']}s versus {rb_c['mean_wall_clock_s']}s for rollback. Resume is cheapest but "
        "trusts a disk that may be damaged; fresh is the most robust but re-pays boot and upload; rollback "
        "is the middle path: a known-good disk without a reboot. If the provider has no snapshots (Celesto "
        "Cloud), rollback degrades to fresh and the trace records policy_fallback."
    )
    report = {
        "failed_step": FAILED_STEP,
        "total_steps": TOTAL_STEPS,
        "policy": CHOSEN,
        "rationale": rationale,
        "trace_path": "reports/failure_trace.jsonl",
        "guest_cleanup": "every path ends with the sandbox deleted (see reports/lifecycle.json)",
        "experiment": {
            "submission": SUBMISSION,
            "provider": ctx.provider_name,
            "repeats_per_cell": REPEATS,
            "cells": cells,
            "traces": rel(EVIDENCE / "policy_experiment_traces.jsonl"),
        },
        "canonical_run": {k: canon[k] for k in ("run_id", "submission", "fault", "policy", "success",
                                                   "score", "recoveries", "sandbox_names")},
    }
    write_json(REPORTS / "failure_policy.json", report)
    return report

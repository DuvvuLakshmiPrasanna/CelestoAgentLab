"""Reliability eval: 20 end-to-end runs, each in a brand-new sandbox."""

from __future__ import annotations

import statistics
from typing import Any

from agent import fixtures
from agent.factory import build_job
from agent.pipeline import JobConfig
from agent.stats import summarize_runs
from scripts._common import EVIDENCE, REPORTS, Ctx, environment_info, rel, write_json

# Pass 1: every fixture once, no injected fault.
# Pass 2: every fixture again; four of them get a step-7 fault so recovery is exercised
# inside the eval itself, not only in a side experiment.
PASS2_FAULTS = {
    "wrong_fib_off_by_one": "transient",
    "correct_basic": "corrupt",
    "infinite_loop_prime": "transient",
    "tamper_results": "corrupt",
}
POLICY = "rollback"


def plan() -> list[tuple[str, str | None]]:
    names = fixtures.list_submissions()
    return [(n, None) for n in names] + [(n, PASS2_FAULTS.get(n)) for n in names]


def run_eval(ctx: Ctx) -> dict[str, Any]:
    trace_path = EVIDENCE / "eval_traces.jsonl"
    rows: list[dict[str, Any]] = []
    for index, (submission, fault) in enumerate(plan(), start=1):
        cfg = JobConfig(submission=submission, policy=POLICY, fault=fault)
        job = build_job(cfg, ctx.settings, emulated=True, audit=ctx.audit,
                        trace_path=trace_path, use_ledger=ctx.ledger_url is not None,
                        provider=ctx.provider)
        result = job.run()
        rows.append({
            "sandbox_name": result["sandbox_names"][0],
            "fresh": True,
            "success": result["success"],
            "wall_clock_s": result["wall_clock_s"],
            "boot_to_ready_s": result["boot_to_ready_s"],
            "cost_usd": result["cost_usd"],
            "run_id": result["run_id"],
            "submission": submission,
            "category": fixtures.category(submission),
            "fault_injected": fault,
            "policy": POLICY,
            "recoveries": result["recoveries"],
            "sandboxes_used": result["sandbox_names"],
            "score": result["score"],
            "expected_score": result["expected_score"],
            "tamper_detected": result["tamper_detected"],
            "error": result["error"],
        })
        print(f"  eval {index:2d}/20 {submission:22s} fault={str(fault):9s} "
              f"success={result['success']} wall={result['wall_clock_s']:.2f}s", flush=True)
    summary = summarize_runs(rows)
    report = {
        **summary,
        "runs": rows,
        "postmortem_path": "reports/postmortem.md",
        "provider": ctx.provider_name,
        "cost_model": (f"modeled: billed wall seconds of every sandbox x ${ctx.settings.price_per_hour}/h "
                       "(Celesto Micro rate). The emulator is free to run; no money was spent."),
        "success_definition": ("all 10 steps completed AND the harness-computed score equals the "
                               "independently known expected score of that fixture (and tampering "
                               "was flagged for the tamper fixture)."),
        "environment": environment_info(),
        "mean_wall_clock_s": round(statistics.fmean(r["wall_clock_s"] for r in rows), 4),
    }
    write_json(REPORTS / "reliability.json", report)
    return report

"""Regenerate every report in reports/ and logs/commands.jsonl from fresh measurements.

    EMULATE_CELESTO=1 python -m scripts.generate_reports [--ledger-url http://localhost:8080]

Needs Linux and root: the experiments are hard-wired to the namespace-jail
provider (scripts/_common.py::make_ctx). They do NOT run on real Celesto yet;
only `python -m agent.cli run` and POST /api/jobs use the real provider path.
See README, 'Running on real Celesto'.
"""

from __future__ import annotations

import argparse
import json
import time

from scripts import _common as C
from scripts.exp_concurrency import run_concurrency
from scripts.exp_containment import run_containment
from scripts.exp_eval import run_eval
from scripts.exp_failure import canonical_trace, run_policy_matrix, write_policy_report
from scripts.exp_lifecycle import run_lifecycle
from scripts.static_reports import write_capabilities, write_postmortem, write_problem


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ledger-url", default=None, help="post run states to this ledger API")
    args = parser.parse_args()
    t0 = time.time()
    C.reset_outputs()
    ctx = C.make_ctx(args.ledger_url)
    print(f"provider={ctx.provider_name} ledger={args.ledger_url}")

    print("[1/6] lifecycle")
    lifecycle = run_lifecycle(ctx)
    print("[2/6] reliability eval (20 fresh sandboxes)")
    reliability = run_eval(ctx)
    print("[3/6] step-7 failure policy matrix + canonical trace")
    cells = run_policy_matrix(ctx)
    canon = canonical_trace(ctx)
    policy = write_policy_report(ctx, cells, canon)
    print("[4/6] containment")
    containment = run_containment(ctx)
    print("[5/6] concurrency")
    concurrency = run_concurrency(ctx)
    print("[6/6] static reports")
    write_problem()
    write_capabilities(ctx, containment["blocked"])
    write_postmortem(ctx, reliability, policy, containment, concurrency)

    leftovers = ctx.provider.list_names()
    summary = {
        "success_rate": reliability["success_rate"], "runs": reliability["run_count"],
        "cleanup": [lifecycle["cleanup_on_success"], lifecycle["cleanup_on_failure"],
                    lifecycle["cleanup_on_interrupt"]],
        "containment_blocked": containment["blocked"], "host_untouched": containment["host_untouched"],
        "leftover_sandboxes": leftovers, "seconds": round(time.time() - t0, 1),
    }
    print(json.dumps(summary, indent=2))
    return 0 if not leftovers else 1


if __name__ == "__main__":
    raise SystemExit(main())

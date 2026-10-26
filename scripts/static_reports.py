"""Hand-authored reports (problem, capabilities) and the data-driven post-mortem."""

from __future__ import annotations

import statistics
from typing import Any

from agent.stats import median
from scripts._common import EVIDENCE, REPORTS, Ctx, rel, write_json


def write_problem() -> None:
    write_json(REPORTS / "problem.json", {
        "who": ("Teaching assistants and instructors of programming courses (and bootcamp or hiring-test "
                "operators) who must grade hundreds of untrusted student submissions without letting a "
                "fork bomb, a forged score file or a prompt-injected note touch their own machine."),
        "agent_work": ("For each submission the agent boots a fresh sandbox, uploads the student's solution "
                       "and a hidden-test grader, runs visible then hidden tests (one child process per "
                       "case with time and memory limits), detects tampering with the grader's output, "
                       "computes the score itself and writes a verified grade.json."),
        "proof_output": ("A grade.json produced inside the sandbox whose score equals an independently known "
                         "expected score, plus a command audit log and a deleted sandbox."),
        "idea_source": "idea_bank",
        "idea_bank_reference": "3. Education and assessment: Hostile-submission autograder",
    })


def write_capabilities(ctx: Ctx, matrix_ok: bool) -> None:
    write_json(REPORTS / "capabilities.json", {
        "capabilities": [
            {
                "id": "safety_hooks",
                "why": ("Every command the agent requests passes agent/guard.py BEFORE the guest sees it; a blocked "
                        "command still gets an audit line. Measured: the hook alone stops the 6 plain exfiltration "
                        "attempts and 6 of 7 destructive commands, but 3 deliberately obfuscated ones get through, "
                        "which is why it is a speed bump and not the boundary. On Celesto local the same guard is also "
                        "attached as an SDK Callback raising CommandBlockedError."),
                "evidence_path": "reports/evidence/attack_matrix.json",
            },
            {
                "id": "network_policy",
                "why": ("Guests start with internet OFF (Celesto internet_settings mode off; in the emulator a network "
                        "namespace with no interfaces). A real attacker socket on the host received the canary in 8 of 9 "
                        "attacks with no defence and in 0 of 9 with network policy on, even with the hook switched "
                        "off. This is the control that actually stops prompt-injection exfiltration."),
                "evidence_path": "reports/evidence/containment.log",
            },
            {
                "id": "snapshots",
                "why": ("A snapshot is taken at step 5, before the risky test steps. When step 7 of 10 fails the chosen "
                        "policy 'rollback' restores it and resumes at step 6, so a destroyed workspace costs seconds, not "
                        "a reboot. Also used to undo a wiped workspace in the destructive-command test. Celesto Cloud has "
                        "no snapshots, so there rollback degrades to fresh and the trace says so."),
                "evidence_path": "reports/failure_trace.jsonl",
            },
            {
                "id": "persistence",
                "why": ("Stop/start keeps the guest disk: files written before stop were read back after start, while "
                        "commands against a stopped guest are refused. Persistence is what makes the 'resume' policy "
                        "possible, and the measurements show where it is not enough (a corrupted disk stays corrupted)."),
                "evidence_path": "reports/evidence/lifecycle.log",
            },
        ],
        "provider_note": (f"Numbers in this repository were produced on '{ctx.provider_name}', a Linux-namespace "
                          "stand-in. The Celesto code path (agent/providers/celesto_provider.py) is implemented against "
                          "celesto 0.1.8 but has not been run against a live Celesto service."),
    })


def write_postmortem(ctx: Ctx, rel_report: dict[str, Any], policy_report: dict[str, Any],
                     containment: dict[str, Any], concurrency: dict[str, Any]) -> None:
    runs = rel_report["runs"]
    failures = [r for r in runs if not r["success"]]
    recovered = [r for r in runs if r["success"] and r["recoveries"] > 0]
    by_cat: dict[str, list[float]] = {}
    for r in runs:
        by_cat.setdefault(r["category"], []).append(r["wall_clock_s"])
    slow = sorted(runs, key=lambda r: -r["wall_clock_s"])[:3]
    fault_runs = [r for r in runs if r["fault_injected"]]
    clean = [r["wall_clock_s"] for r in runs if not r["fault_injected"]]
    faulty = [r["wall_clock_s"] for r in fault_runs]

    lines = [
        "# Post-mortem: 20-run reliability eval",
        "",
        f"Provider: **{ctx.provider_name}** (a Linux namespace jail, not a Celesto microVM; see the README). "
        f"Cost is modeled at ${ctx.settings.price_per_hour}/h per sandbox, not billed.",
        "",
        "## Result",
        "",
        f"- {rel_report['run_count']} runs, each in a brand-new uniquely named sandbox.",
        f"- Success rate **{rel_report['success_rate']:.1%}**, median wall clock {rel_report['median_wall_clock_s']}s, "
        f"p90 {rel_report['p90_wall_clock_s']}s, median boot-to-ready {rel_report['median_boot_to_ready_s']}s, "
        f"total modeled cost ${rel_report['total_cost_usd']}.",
        f"- 'Success' is strict: all 10 steps finished AND the harness-computed score equals the fixture's "
        f"independently known expected score (tamper must also be flagged for the tamper fixture).",
        "",
    ]
    if failures:
        lines += ["## Failures", ""]
        for r in failures:
            lines += [f"- Run `{r['sandbox_name']}` ({r['submission']}, fault={r['fault_injected']}): "
                      f"{r['error'] or 'score ' + str(r['score']) + ' != expected ' + str(r['expected_score'])}."]
        lines += [""]
    else:
        lines += [
            "## Failures",
            "",
            "None in this eval. That is a statement about this test set, not about the system: the 10 fixtures are "
            "deterministic, the planner is scripted (no LLM key was available), and the emulator has no network "
            "latency, no cold-image downloads and no provider rate limits. A 100% here should be read as "
            "'the harness logic is sound', not 'Celesto runs will be 100%'. The first real-Celesto run is expected "
            "to expose boot failures, SDK timeouts and image-pull stalls that this eval cannot.",
            "",
        ]
    lines += [
        "## What did go wrong (during development, before the eval)",
        "",
        "Seven real incidents are written up in `docs/dev_failures.md` (forged results scoring 150/100, rollback "
        "restoring into a deleted guest, a hostile submission being mistaken for an infrastructure fault, a hook "
        "that blocked only 2 of 7 destructive commands, an attack that never ran, Ctrl-C silently ignored, and a "
        "refactor that broke the harness API and was caught by the test suite). Each changed the design or the "
        "process. The eval above was run only after those were fixed, so it measures the fixed system.",
        "",
        "## Recovered runs (failure injected at step 7, policy rollback)",
        "",
    ]
    for r in recovered:
        lines.append(f"- `{r['sandbox_name']}` {r['submission']} fault={r['fault_injected']}: recovered "
                     f"{r['recoveries']}x, final score {r['score']} (expected {r['expected_score']}), "
                     f"{r['wall_clock_s']}s.")
    if faulty and clean:
        lines += ["", f"A fault-injected run took a median {statistics.median(faulty):.2f}s versus "
                      f"{statistics.median(clean):.2f}s for a clean one: recovery costs about "
                      f"{statistics.median(faulty) - statistics.median(clean):.2f}s here."]
    lines += ["", "## Where the time goes", ""]
    for cat, vals in sorted(by_cat.items()):
        lines.append(f"- {cat}: median {median(vals):.2f}s over {len(vals)} runs")
    lines += [f"- slowest: " + ", ".join(f"{r['submission']} ({r['wall_clock_s']}s)" for r in slow) + ". "
              "The infinite-loop submission always costs one full per-case timeout (3s) because the grader "
              "must wait to be sure it is not merely slow; that wait is the price of not trusting the student.",
              "", "## Threats to validity", "",
              "- Emulated provider: shares the host kernel; boot-to-ready is tens of milliseconds, a real "
              "microVM is ~500 ms and a cloud computer more. Re-run `scripts/generate_reports.py` on Celesto.",
              "- Scripted planner: the shipped eval never exercised an LLM. The injection test uses a worst-case "
              "'compromised' planner instead, so its result does not depend on model behaviour.",
              "- Fixtures are small and written by the author; hidden-test coverage is only 8 cases.",
              "- Cost is modeled from wall time, not read from a bill.", "",
              "## What I would change next", "",
              "1. Run the same eval on Celesto local (KVM) and cloud and publish both tables.",
              "2. Add a real LLM planner run and measure how often the model follows the poisoned note.",
              "3. Replace the pattern hook with an allow-list of commands for step 3, because a deny-list is "
              f"bypassable (measured: {containment['attack_success_rate']['hook_only']:.0%} attack success with the hook alone).",
              ""]
    text = "\n".join(lines)
    (REPORTS / "postmortem.md").write_text(text, encoding="utf-8")

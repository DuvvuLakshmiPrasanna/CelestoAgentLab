"""Lifecycle experiments: cleanup on success, failure and interrupt, plus persistence.

Every boolean in reports/lifecycle.json is computed from an observation made here
(directory gone, trace event present, no process left), never hard-coded.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from typing import Any

from agent.factory import build_job
from agent.naming import is_valid_name
from agent.pipeline import JobConfig
from agent.session import REGISTRY
from scripts._common import EVIDENCE, LOGS, REPORTS, ROOT, Ctx, rel, write_json


def _gone(ctx: Ctx, names: list[str]) -> bool:
    live = set(ctx.provider.list_names())
    return all(n not in live for n in names)


def _trace_has_delete(events: list[dict], names: list[str]) -> bool:
    deleted = {e["sandbox_name"] for e in events if e["event"] == "sandbox_deleted"}
    return all(n in deleted for n in names)


def check_success(ctx: Ctx, log: list[str]) -> dict[str, Any]:
    job = build_job(JobConfig(submission="correct_basic", policy="rollback"), ctx.settings, emulated=True,
                    audit=ctx.audit, use_ledger=False, provider=ctx.provider)
    result = job.run()
    ok = result["success"] and _gone(ctx, result["sandbox_names"]) and _trace_has_delete(job.trace.events, result["sandbox_names"])
    log.append(f"[success]   run {result['run_id']} succeeded={result['success']}; guests {result['sandbox_names']} "
               f"deleted={_gone(ctx, result['sandbox_names'])}; sandbox_deleted trace event present="
               f"{_trace_has_delete(job.trace.events, result['sandbox_names'])}")
    return {"ok": ok, "names": result["sandbox_names"]}


def check_failure(ctx: Ctx, log: list[str]) -> dict[str, Any]:
    """An UNRECOVERED failure (resume policy cannot repair a destroyed workspace)."""
    job = build_job(JobConfig(submission="correct_basic", policy="resume", fault="corrupt"), ctx.settings,
                    emulated=True, audit=ctx.audit, use_ledger=False, provider=ctx.provider)
    result = job.run()
    failed = not result["success"]
    ok = failed and _gone(ctx, result["sandbox_names"]) and _trace_has_delete(job.trace.events, result["sandbox_names"])
    log.append(f"[failure]   run {result['run_id']} failed as intended={failed} ({result['error']}); guests "
               f"{result['sandbox_names']} deleted={_gone(ctx, result['sandbox_names'])}")
    return {"ok": ok, "names": result["sandbox_names"]}


def check_exception(ctx: Ctx, log: list[str]) -> dict[str, Any]:
    """An UNEXPECTED exception escaping a step (not a StepFailed) must still delete the guest."""
    from agent import pipeline

    job = build_job(JobConfig(submission="correct_basic", policy="rollback"), ctx.settings, emulated=True,
                    audit=ctx.audit, use_ledger=False, provider=ctx.provider)
    original = pipeline.Job._s4_syntax

    def boom(self, h, st):  # noqa: ANN001
        raise RuntimeError("simulated harness bug at step 4")

    pipeline.Job._s4_syntax = boom
    raised = False
    try:
        job.run()
    except RuntimeError:
        raised = True
    finally:
        pipeline.Job._s4_syntax = original
    names = job.sandbox_names
    ok = raised and _gone(ctx, names) and _trace_has_delete(job.trace.events, names)
    log.append(f"[exception] an unexpected RuntimeError escaped step 4 (propagated={raised}); guests {names} "
               f"deleted={_gone(ctx, names)}")
    return {"ok": ok, "names": names}


def check_interrupt(ctx: Ctx, sig: signal.Signals, log: list[str]) -> dict[str, Any]:
    env = dict(os.environ, EMULATE_CELESTO="1", LOGS_DIR=str(LOGS), EMULATOR_HOME=str(ctx.settings.emulator_home),
               LEDGER_URL="")
    proc = subprocess.Popen(
        [sys.executable, "-m", "agent.cli", "run", "--no-ledger", "--hold-seconds", "30"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env, cwd=ROOT)
    live: list[str] = []
    deadline = time.time() + 15
    while time.time() < deadline and not live:
        time.sleep(0.2)
        live = ctx.provider.list_names()
    time.sleep(1.0)  # let the job reach the held step inside the guest
    proc.send_signal(sig)
    out, err = proc.communicate(timeout=40)
    try:
        payload = json.loads(out.strip().splitlines()[-1])
    except Exception:  # noqa: BLE001
        payload = {}
    names = payload.get("sandboxes", live)
    stray = subprocess.run(["pgrep", "-f", "sleep 30"], capture_output=True, text=True).stdout.split()
    ok = (bool(live) and proc.returncode == 130 and _gone(ctx, names) and not payload.get("still_live")
          and not stray)
    log.append(f"[interrupt] {sig.name} sent to a running job while guest {live} was busy; exit code "
               f"{proc.returncode} (130 = interrupted); guests {names} deleted={_gone(ctx, names)}; "
               f"stray guest processes={len(stray)}")
    return {"ok": ok, "names": names}


def check_persistence(ctx: Ctx, log: list[str]) -> dict[str, Any]:
    from agent.guard import SafetyGuard
    from agent.naming import new_run_id
    from agent.session import managed_sandbox
    from agent.trace import TraceWriter

    with managed_sandbox(ctx.provider, run_id=new_run_id(), guard=SafetyGuard(), audit=ctx.audit,
                         trace=TraceWriter("persistence"), price_per_hour=ctx.settings.price_per_hour,
                         network=False, env={}) as h:
        h.probe()
        h.sb.write_file("/workspace/state.txt", "checkpoint-A\n")
        h.sb.run("python3 -c \"open('/root/session.log','w').write('step 4 of 10 done')\"")
        h.sb.stop()
        stopped = False
        try:
            h.sb.run("echo should-not-run")
        except Exception:  # noqa: BLE001
            stopped = True
        h.sb.start()
        back = h.sb.run("cat /workspace/state.txt /root/session.log")
        survived = "checkpoint-A" in back.stdout and "step 4 of 10 done" in back.stdout
        log.append(f"[persistence] guest {h.name} stopped (commands refused while stopped={stopped}), started "
                   f"again; /workspace and /root files survived={survived}")
        return {"ok": stopped and survived, "names": [h.name]}


def run_lifecycle(ctx: Ctx) -> dict[str, Any]:
    log: list[str] = ["LIFECYCLE EVIDENCE", f"provider: {ctx.provider_name}", ""]
    checks = {
        "success": check_success(ctx, log),
        "failure": check_failure(ctx, log),
        "exception": check_exception(ctx, log),
        "interrupt_sigint": check_interrupt(ctx, signal.SIGINT, log),
        "interrupt_sigterm": check_interrupt(ctx, signal.SIGTERM, log),
        "persistence": check_persistence(ctx, log),
    }
    for name, c in checks.items():
        print(f"  lifecycle {name:18s} ok={c['ok']}", flush=True)
    leftovers = ctx.provider.list_names()
    names: list[str] = []
    for c in checks.values():
        for n in c["names"]:
            if n not in names and is_valid_name(n):
                names.append(n)
    log += ["", f"guests alive after ALL lifecycle checks: {leftovers}",
            f"process-wide registry still holding live guests: {REGISTRY.live()}"]
    path = EVIDENCE / "lifecycle.log"
    path.write_text("\n".join(log) + "\n", encoding="utf-8")
    report = {
        "cleanup_on_success": bool(checks["success"]["ok"]),
        "cleanup_on_failure": bool(checks["failure"]["ok"] and checks["exception"]["ok"]),
        "cleanup_on_interrupt": bool(checks["interrupt_sigint"]["ok"] and checks["interrupt_sigterm"]["ok"]),
        "sandbox_names": names,
        "persistence_stop_start_ok": bool(checks["persistence"]["ok"]),
        "leftover_sandboxes": leftovers,
        "evidence_path": rel(path),
        "mechanisms": {
            "normal_and_failure_paths": "agent/session.py::managed_sandbox (try/finally around every guest)",
            "interrupt": "agent/session.py::install_signal_handlers turns SIGTERM/SIGHUP into KeyboardInterrupt; "
                         "Ctrl-C already is one; the finally block runs, and the in-flight guest command is killed",
            "backstop": "agent/session.py::CleanupRegistry + atexit; `python -m agent.cli reap`",
            "name_collisions": "agent/naming.py: sbx- + 40 random bits, never reused in-process; providers refuse duplicates",
        },
    }
    write_json(REPORTS / "lifecycle.json", report)
    return report

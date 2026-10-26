"""The 10-step grading task, with a named recovery policy for a failure at step 7.

  1 boot_probe      2 upload_inputs   3 env_probe      4 syntax_check   5 checkpoint
  6 visible_tests   7 hidden_tests    8 integrity      9 score         10 publish_proof

Step 7 is the designed crash. When a step fails, exactly one recovery is applied:

  resume    stop/start the same guest (disk survives), retry the failed step
  rollback  restore the step-5 snapshot, re-run steps 6..10 (needs snapshots)
  fresh     delete the guest, create a new uniquely named one, re-run steps 1..10

Every path ends with every guest deleted: success, failure, an unexpected bug in a
step, and Ctrl-C / SIGTERM. Unexpected exceptions are re-raised AFTER cleanup so a
harness bug is never reported as a graded failure.
"""

from __future__ import annotations

import hashlib
import json
import time
from contextlib import ExitStack
from dataclasses import dataclass, field
from typing import Any

from agent import fixtures
from agent.audit import CommandAudit
from agent.errors import CommandBlocked, HarnessError, StepFailed
from agent.guard import SafetyGuard
from agent.ledger_client import LedgerClient
from agent.naming import new_run_id
from agent.planner import Planner, ScriptedPlanner
from agent.providers.base import Provider
from agent.session import SandboxHandle, managed_sandbox
from agent.trace import TraceWriter

STEP_NAMES = [
    "boot_probe", "upload_inputs", "env_probe", "syntax_check", "checkpoint",
    "visible_tests", "hidden_tests", "integrity_check", "score", "publish_proof",
]
FAILED_STEP = 7
TOTAL_STEPS = 10
POLICIES = ("resume", "rollback", "fresh")
FAULTS = (None, "transient", "corrupt")
PROBLEM_ID = "grade-student-submission"
CHECKPOINT = "ckpt-step5"
_SUITE_STEP = {"visible": 6, "hidden": 7}


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class JobConfig:
    submission: str
    policy: str = "rollback"
    fault: str | None = None  # None | "transient" (guest killed mid-step 7) | "corrupt" (workspace damaged)
    run_id: str | None = None
    notes: str = fixtures.BENIGN_NOTES
    env: dict[str, str] = field(default_factory=dict)
    network: bool = False
    hidden_timeout_s: float = 3.0
    hold_seconds: float = 0.0  # keep the guest busy in step 3 (used by the interrupt test)

    def __post_init__(self) -> None:
        if self.policy not in POLICIES:
            raise ValueError(f"policy must be one of {POLICIES}, got {self.policy!r}")
        if self.fault not in FAULTS:
            raise ValueError(f"fault must be one of {FAULTS}, got {self.fault!r}")
        if self.submission not in fixtures.list_submissions():
            raise ValueError(f"unknown submission {self.submission!r}")


@dataclass
class JobState:
    source: bytes
    solution_sha: str = ""
    visible: dict[str, Any] | None = None
    hidden: dict[str, Any] | None = None
    syntax_ok: bool | None = None
    network_probe: dict[str, str] = field(default_factory=dict)
    blocked: list[dict[str, str]] = field(default_factory=list)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    snapshot_taken: bool = False
    tamper_detected: bool = False
    score: float | None = None
    proof: dict[str, Any] | None = None
    fault: str | None = None  # consumed the first time step 7 runs


class Job:
    def __init__(
        self,
        cfg: JobConfig,
        *,
        provider: Provider,
        guard: SafetyGuard,
        audit: CommandAudit,
        planner: Planner | None = None,
        ledger: LedgerClient | None = None,
        trace: TraceWriter | None = None,
        price_per_hour: float = 0.015,
    ) -> None:
        self.cfg = cfg
        self.run_id = cfg.run_id or new_run_id()
        self.provider, self.guard, self.audit = provider, guard, audit
        self.planner = planner or ScriptedPlanner()
        self.ledger = ledger or LedgerClient(None)
        self.trace = trace or TraceWriter(self.run_id)
        self.price_per_hour = price_per_hour
        self.sandbox_names: list[str] = []
        self.handles: list[SandboxHandle] = []
        self.steps: list[dict[str, Any]] = []

    # ------------------------------------------------------------------ steps
    def _s1_boot(self, h: SandboxHandle, st: JobState) -> None:
        h.probe()

    def _s2_upload(self, h: SandboxHandle, st: JobState) -> None:
        h.sb.write_file("/workspace/solution.py", st.source)
        h.sb.write_file("/workspace/runner.py", fixtures.asset("runner.py"))
        h.sb.write_file("/workspace/netprobe.py", fixtures.asset("netprobe.py"))
        h.sb.write_file("/workspace/notes.md", self.cfg.notes)
        st.solution_sha = _sha(st.source)

    def _s3_probe(self, h: SandboxHandle, st: JobState) -> None:
        # The agent's discretionary step: it reads UNTRUSTED student notes and chooses commands.
        for cmd in self.planner.diagnostics(self.cfg.notes):
            try:
                res = h.sb.run(cmd, timeout=20)
            except CommandBlocked as blocked:
                st.blocked.append({"command": cmd[:160], "rule": blocked.rule})
                self.trace.event("injected_command_blocked", command=cmd[:160], rule=blocked.rule,
                                 sandbox_name=h.name)
                continue
            st.diagnostics.append({"command": cmd[:160], "exit_code": res.exit_code,
                                   "stderr": res.stderr.strip()[:160]})
            if "netprobe.py" in cmd and res.ok:
                try:
                    st.network_probe = json.loads(res.stdout.strip().splitlines()[-1])
                except (ValueError, IndexError):
                    pass
        if self.cfg.hold_seconds > 0:
            h.sb.run(f"sleep {int(self.cfg.hold_seconds)}", timeout=self.cfg.hold_seconds + 10)

    def _s4_syntax(self, h: SandboxHandle, st: JobState) -> None:
        st.syntax_ok = h.sb.run("python3 -m py_compile solution.py", timeout=20).ok

    def _s5_checkpoint(self, h: SandboxHandle, st: JobState) -> None:
        if "snapshots" in self.provider.capabilities:
            h.sb.snapshot(CHECKPOINT)
            st.snapshot_taken = True
        else:
            self.trace.event("checkpoint_skipped", reason="provider has no snapshots")

    def _run_suite(self, h: SandboxHandle, suite: str, command_timeout: float | None = None) -> dict[str, Any]:
        step = _SUITE_STEP[suite]
        per_case = self.cfg.hidden_timeout_s
        # The runner is re-uploaded before EVERY suite: student code runs in this directory
        # and could have rewritten it during an earlier suite.
        h.sb.write_file("/workspace/runner.py", fixtures.asset("runner.py"))
        h.sb.run(f"rm -f /workspace/results_{suite}.json /workspace/.results_{suite}.tmp", timeout=10)
        budget = command_timeout if command_timeout is not None else 15 + 6 * per_case
        res = h.sb.run(f"python3 runner.py {suite} {per_case}", timeout=budget)
        if res.timed_out:
            raise StepFailed(step, STEP_NAMES[step - 1], "guest process killed before it finished")
        if not res.ok:
            raise StepFailed(step, STEP_NAMES[step - 1],
                             f"runner exit code {res.exit_code}: {res.stderr.strip()[:120]}")
        try:
            data = json.loads(h.sb.read_file(f"/workspace/results_{suite}.json"))
        except Exception as exc:  # noqa: BLE001
            raise StepFailed(step, STEP_NAMES[step - 1], f"no readable results file: {exc}") from exc
        if data.get("suite") != suite or "results" not in data:
            raise StepFailed(step, STEP_NAMES[step - 1], "results file has the wrong shape")
        return data  # captured NOW, before any later student code can touch the file

    def _s6_visible(self, h: SandboxHandle, st: JobState) -> None:
        st.visible = self._run_suite(h, "visible")

    def _s7_hidden(self, h: SandboxHandle, st: JobState) -> None:
        fault, st.fault = st.fault, None
        command_timeout = None
        if fault == "corrupt":
            h.sb.chaos("rm -f /workspace/solution.py")
            self.trace.event("fault_injected", fault="corrupt", detail="solution.py deleted",
                             sandbox_name=h.name)
        elif fault == "transient":
            h.sb.chaos("printf '{\"partial\":' > /workspace/.results_hidden.tmp")
            command_timeout = 0.05
            self.trace.event("fault_injected", fault="transient", detail="guest process killed mid-run",
                             sandbox_name=h.name)
        # Never grade a damaged guest: the student file must be byte-identical to what was uploaded.
        res = h.sb.run("sha256sum /workspace/solution.py", timeout=15)
        if not res.ok or res.stdout.split()[:1] != [st.solution_sha]:
            raise StepFailed(FAILED_STEP, STEP_NAMES[FAILED_STEP - 1],
                             "solution.py is missing or changed in the guest")
        st.hidden = self._run_suite(h, "hidden", command_timeout)

    def _s8_integrity(self, h: SandboxHandle, st: JobState) -> None:
        for suite in ("visible", "hidden"):
            on_disk = json.loads(h.sb.read_file(f"/workspace/results_{suite}.json"))
            if on_disk != getattr(st, suite):
                st.tamper_detected = True
                self.trace.event("tamper_detected", suite=suite, sandbox_name=h.name,
                                 detail="results file differs from what the harness captured")

    def _s9_score(self, h: SandboxHandle, st: JobState) -> None:
        assert st.visible is not None and st.hidden is not None
        total = st.visible["total"] + st.hidden["total"]
        passed = st.visible["passed"] + st.hidden["passed"]
        st.score = round(100.0 * passed / total, 2) if total else 0.0  # from harness memory, never the guest file

    def _s10_proof(self, h: SandboxHandle, st: JobState) -> None:
        proof = {"submission": self.cfg.submission, "score": st.score, "visible": st.visible,
                 "hidden": st.hidden, "sandbox_name": h.name, "tamper_detected": st.tamper_detected}
        h.sb.write_file("/workspace/grade.json", json.dumps(proof, indent=2))
        if json.loads(h.sb.read_file("/workspace/grade.json")) != proof:
            raise StepFailed(10, STEP_NAMES[9], "proof file did not round-trip")
        st.proof = proof

    _STEP_METHODS = ("_s1_boot", "_s2_upload", "_s3_probe", "_s4_syntax", "_s5_checkpoint",
                     "_s6_visible", "_s7_hidden", "_s8_integrity", "_s9_score", "_s10_proof")

    def _execute(self, h: SandboxHandle, st: JobState, first: int) -> None:
        for number in range(first, TOTAL_STEPS + 1):
            name = STEP_NAMES[number - 1]
            h.sb.step = number
            self.trace.event("step_started", step=number, name=name, sandbox_name=h.name)
            began = time.perf_counter()
            try:
                getattr(self, self._STEP_METHODS[number - 1])(h, st)
            except (StepFailed, HarnessError) as exc:
                reason = exc.reason if isinstance(exc, StepFailed) else str(exc)[:160]
                self.steps.append({"step": number, "name": name, "ok": False, "sandbox_name": h.name,
                                   "duration_s": round(time.perf_counter() - began, 4), "reason": reason})
                self.trace.event("step_failed", step=number, name=name, reason=reason, sandbox_name=h.name)
                if isinstance(exc, StepFailed):
                    raise
                raise StepFailed(number, name, reason) from exc
            self.steps.append({"step": number, "name": name, "ok": True, "sandbox_name": h.name,
                               "duration_s": round(time.perf_counter() - began, 4)})
            self.trace.event("step_completed", step=number, name=name, sandbox_name=h.name)
            if number == 1:
                self.trace.event("sandbox_ready", sandbox_name=h.name,
                                 boot_to_ready_s=round(h.boot_to_ready_s, 4))

    # -------------------------------------------------------------------- run
    def _post(self, h: SandboxHandle, state: str) -> None:
        index = self.handles.index(h)
        self.ledger.post_state(self.run_id + ("" if index == 0 else f"-a{index + 1}"),
                               h.name, PROBLEM_ID, state)

    def run(self) -> dict[str, Any]:
        cfg = self.cfg
        started = time.perf_counter()
        st = JobState(source=fixtures.submission_source(cfg.submission), fault=cfg.fault)
        self.trace.event("job_started", submission=cfg.submission, policy=cfg.policy, fault=cfg.fault)
        outcome: dict[str, Any] = {"error": None, "completed": False, "recoveries": 0, "failed_step": None,
                                   "policy_applied": None}
        try:
            with ExitStack() as stack:
                def open_sandbox() -> SandboxHandle:
                    h = stack.enter_context(managed_sandbox(
                        self.provider, run_id=self.run_id, guard=self.guard, audit=self.audit,
                        trace=self.trace, price_per_hour=self.price_per_hour,
                        network=cfg.network, env=cfg.env))
                    self.handles.append(h)
                    self.sandbox_names.append(h.name)
                    self._post(h, "created")
                    return h

                h = open_sandbox()
                first = 1
                while True:
                    try:
                        if first > 1:
                            self._post(h, "running")
                        self._execute(h, st, first)
                        outcome["completed"] = True
                        break
                    except StepFailed as exc:
                        outcome["failed_step"] = exc.step
                        if outcome["recoveries"] >= 1:
                            outcome["error"] = f"step {exc.step} failed again after recovery: {exc.reason}"
                            self.trace.event("recovery_failed", step=exc.step, reason=exc.reason,
                                             sandbox_name=h.name)
                            self._post(h, "failed")
                            break
                        outcome["recoveries"] += 1
                        chosen = cfg.policy
                        if chosen == "rollback" and not st.snapshot_taken:
                            chosen = "fresh"
                            self.trace.event("policy_fallback", requested="rollback", applied="fresh",
                                             reason="no snapshot available (provider lacks snapshots, "
                                                    "or the failure happened before step 5)")
                        outcome["policy_applied"] = chosen
                        self.trace.event("policy_applied", policy=chosen, failed_step=exc.step,
                                         total_steps=TOTAL_STEPS, sandbox_name=h.name, reason=exc.reason)
                        if chosen == "resume":
                            h.sb.stop()   # persistence: pause the guest, keep its disk
                            h.sb.start()  # ...bring the same disk back
                            self.trace.event("guest_stopped_and_started", sandbox_name=h.name)
                            first = exc.step
                        elif chosen == "rollback":
                            h.sb.restore(CHECKPOINT)
                            self.trace.event("snapshot_restored", snapshot=CHECKPOINT, sandbox_name=h.name)
                            first = 6
                        else:  # fresh
                            self._post(h, "failed")
                            h.close()
                            self._post(h, "deleted")
                            h = open_sandbox()
                            st.visible = st.hidden = None
                            first = 1
                        self.trace.event("recovery_started", policy=chosen, resume_from_step=first,
                                         sandbox_name=h.name)
                if outcome["completed"]:
                    self._post(h, "succeeded")
        except KeyboardInterrupt:
            outcome["error"] = "interrupted"
            self.trace.event("job_interrupted", sandbox_names=list(self.sandbox_names))
            raise
        except BaseException as exc:
            self.trace.event("job_crashed", error=f"{type(exc).__name__}: {str(exc)[:200]}")
            raise
        finally:
            for h in self.handles:  # ExitStack already closed them; this is the idempotent backstop
                h.close()
                if h.deleted:
                    self._post(h, "deleted")

        return self._result(st, outcome, time.perf_counter() - started)

    def _result(self, st: JobState, outcome: dict[str, Any], wall: float) -> dict[str, Any]:
        cfg = self.cfg
        expected = fixtures.expected_score(cfg.submission)
        tamper_expected = bool(fixtures._expected().get(cfg.submission, {}).get("expect_integrity_violation"))
        all_deleted = bool(self.handles) and all(h.deleted for h in self.handles)
        graded = (outcome["completed"] and st.score is not None and expected is not None
                  and abs(st.score - expected) < 0.01 and st.tamper_detected == tamper_expected)
        result = {
            "run_id": self.run_id, "submission": cfg.submission, "policy": cfg.policy, "fault": cfg.fault,
            "policy_applied": outcome["policy_applied"], "recoveries": outcome["recoveries"],
            "failed_step": outcome["failed_step"],
            "success": bool(graded and all_deleted and not outcome["error"]),
            "graded_correctly": bool(graded), "error": outcome["error"],
            "score": st.score, "expected_score": expected,
            "syntax_ok": st.syntax_ok, "tamper_detected": st.tamper_detected, "tamper_expected": tamper_expected,
            "blocked_commands": st.blocked, "diagnostics": st.diagnostics, "network_probe": st.network_probe,
            "sandbox_names": list(self.sandbox_names), "all_deleted": all_deleted,
            "cleanup_errors": [h.cleanup_error for h in self.handles if h.cleanup_error],
            "steps": self.steps, "steps_ok": sum(1 for s in self.steps if s["ok"]),
            "wall_clock_s": round(wall, 4),
            "boot_to_ready_s": round(self.handles[0].boot_to_ready_s, 4) if self.handles else 0.0,
            "cost_usd": round(sum(h.cost_usd() for h in self.handles), 8),
            "provider": self.handles[0].sb.provider if self.handles else None,
            "ledger_posts": self.ledger.posts, "ledger_ok": self.ledger.ok,
        }
        self.trace.event("job_finished", success=result["success"], score=st.score,
                         wall_clock_s=result["wall_clock_s"], sandbox_names=result["sandbox_names"])
        return result

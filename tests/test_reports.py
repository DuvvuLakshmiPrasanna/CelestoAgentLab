"""Contract tests for every shipped report file.

Deliberately stdlib-only and independent of the project's own code: the
statistics are re-implemented here from the written contract so that a bug in
agent/stats.py cannot hide itself. Run:  pytest tests/test_reports.py
"""

from __future__ import annotations

import json
import math
import re
from datetime import datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
NAME_RE = re.compile(r"^sbx-[a-z0-9]{8,}$")
CAPABILITY_IDS = {"persistence", "snapshots", "celestofs", "browser", "published_ports",
                  "network_policy", "safety_hooks", "host_mounts", "coding_agent_preset",
                  "agentor_durable"}


def load(name: str):
    return json.loads((REPORTS / name).read_text(encoding="utf-8"))


def command_log() -> list[dict]:
    path = ROOT / "logs" / "commands.jsonl"
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


# ---------------------------------------------------------------- problem.json
def test_problem_json():
    data = load("problem.json")
    for key in ("who", "agent_work", "proof_output", "idea_source"):
        assert key in data
    assert len(data["who"]) >= 40
    assert len(data["agent_work"]) >= 40
    assert len(data["proof_output"]) >= 20
    assert data["idea_source"] in ("idea_bank", "original")


# ------------------------------------------------------------ commands.jsonl
def test_command_log_schema():
    entries = command_log()
    assert len(entries) >= 1
    for i, e in enumerate(entries, 1):
        assert NAME_RE.match(e["sandbox_name"]), f"line {i}: bad sandbox_name {e['sandbox_name']!r}"
        assert isinstance(e["command"], str) and e["command"].strip(), f"line {i}: empty command"
        assert e["decision"] in ("allow", "block"), f"line {i}"
        assert e["execution_target"] == "celesto_sandbox", f"line {i}"
        datetime.fromisoformat(e["ts"].replace("Z", "+00:00"))


def test_command_log_records_blocked_commands():
    assert any(e["decision"] == "block" for e in command_log()), "blocked commands must still be logged"


# ---------------------------------------------------------- capabilities.json
def test_capabilities():
    caps = load("capabilities.json")["capabilities"]
    assert len(caps) >= 2
    ids = [c["id"] for c in caps]
    assert len(ids) == len(set(ids)), "ids must be unique"
    for c in caps:
        assert c["id"] in CAPABILITY_IDS
        assert len(c["why"]) >= 80
        assert (ROOT / c["evidence_path"]).is_file(), f"missing evidence: {c['evidence_path']}"


# -------------------------------------------------------------- lifecycle.json
def test_lifecycle():
    data = load("lifecycle.json")
    assert data["cleanup_on_success"] is True
    assert data["cleanup_on_failure"] is True
    assert data["cleanup_on_interrupt"] is True
    names = data["sandbox_names"]
    assert names and len(names) == len(set(names))
    in_log = {e["sandbox_name"] for e in command_log()}
    in_reliability = {r["sandbox_name"] for r in load("reliability.json")["runs"]}
    for n in names:
        assert NAME_RE.match(n)
        assert n in in_log or n in in_reliability, f"{n} not in the command log or reliability.json"
    assert data["leftover_sandboxes"] == [], "a sandbox was left behind"


# ----------------------------------------------------------- reliability.json
def _median(values):
    s = sorted(values)
    n = len(s)
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def test_reliability_arithmetic():
    data = load("reliability.json")
    runs = data["runs"]
    n = len(runs)
    assert n >= 20 and data["run_count"] == n
    names = [r["sandbox_name"] for r in runs]
    assert len(set(names)) == n, "sandbox names must be unique"
    for r in runs:
        assert NAME_RE.match(r["sandbox_name"])
        assert r["fresh"] is True
        assert isinstance(r["success"], bool)
        for key in ("wall_clock_s", "boot_to_ready_s", "cost_usd"):
            assert isinstance(r[key], (int, float)) and not isinstance(r[key], bool) and r[key] >= 0
    successes = sum(1 for r in runs if r["success"])
    assert abs(data["success_rate"] - successes / n) <= 0.001
    walls = sorted(r["wall_clock_s"] for r in runs)
    assert abs(data["median_wall_clock_s"] - _median(walls)) <= 0.001
    p90 = walls[math.ceil(0.90 * n) - 1]
    assert abs(data["p90_wall_clock_s"] - p90) <= 0.001
    assert abs(data["median_boot_to_ready_s"] - _median([r["boot_to_ready_s"] for r in runs])) <= 0.001
    assert abs(data["total_cost_usd"] - sum(r["cost_usd"] for r in runs)) <= 0.01
    assert data["postmortem_path"] == "reports/postmortem.md"
    assert len((ROOT / data["postmortem_path"]).read_text(encoding="utf-8")) >= 200


def test_reliability_failures_not_hidden():
    """Rows must not have been filtered: every run in the eval trace appears in the report."""
    data = load("reliability.json")
    trace = REPORTS / "evidence" / "eval_traces.jsonl"
    started = {json.loads(l)["run_id"] for l in trace.read_text().splitlines()
               if l.strip() and json.loads(l)["event"] == "job_started"}
    assert started == {r["run_id"] for r in data["runs"]}


def test_reliability_names_in_command_log():
    in_log = {e["sandbox_name"] for e in command_log()}
    for r in load("reliability.json")["runs"]:
        assert r["sandbox_name"] in in_log


# ------------------------------------------------------------ containment.json
def test_containment():
    data = load("containment.json")
    assert data["attack"] in ("prompt_injection_exfil", "destructive_command", "suspicious_package")
    assert data["blocked"] is True
    assert data["host_untouched"] is True
    assert data["evidence_paths"]
    for p in data["evidence_paths"]:
        assert (ROOT / p).is_file(), f"missing evidence file {p}"


def test_containment_numbers_are_consistent():
    """The headline claim must be backed by the raw attack matrix, not just asserted."""
    matrix = json.loads((REPORTS / "evidence" / "attack_matrix.json").read_text())
    cfgs = matrix["configs"]
    assert cfgs["none"]["leaks"] > 0, "the control must leak, otherwise the test proves nothing"
    assert cfgs["both"]["leaks"] == 0
    assert cfgs["network_only"]["leaks"] == 0
    assert matrix["destructive"]["host_untouched"] is True
    for name, cfg in cfgs.items():
        assert cfg["leaks"] == sum(1 for r in cfg["detail"] if r["leaked"]), name


# ---------------------------------------------------------- failure_policy.json
def test_failure_policy():
    data = load("failure_policy.json")
    assert data["failed_step"] == 7 and data["total_steps"] == 10
    assert data["policy"] in ("resume", "rollback", "fresh")
    assert len(data["rationale"]) >= 200
    assert data["trace_path"] == "reports/failure_trace.jsonl"
    lines = [json.loads(l) for l in (ROOT / data["trace_path"]).read_text().splitlines() if l.strip()]
    applied = [e for e in lines if e.get("event") == "policy_applied" and e.get("policy") == data["policy"]]
    assert applied, "no policy_applied line with the policy named in failure_policy.json"
    assert applied[0]["failed_step"] == 7


def test_failure_trace_ends_in_deleted_sandbox():
    lines = [json.loads(l) for l in (REPORTS / "failure_trace.jsonl").read_text().splitlines() if l.strip()]
    created = {e["sandbox_name"] for e in lines if e["event"] == "sandbox_created"}
    deleted = {e["sandbox_name"] for e in lines if e["event"] == "sandbox_deleted"}
    assert created and created <= deleted


# -------------------------------------------------------------- concurrency.json
def test_concurrency():
    data = load("concurrency.json")
    jobs = data["jobs"]
    assert len(jobs) >= 5
    names = [j["sandbox_name"] for j in jobs]
    assert len(set(names)) == len(names)
    for j in jobs:
        assert NAME_RE.match(j["sandbox_name"])
        assert isinstance(j["started_at"], str) and j["started_at"].strip()
        datetime.fromisoformat(j["started_at"].replace("Z", "+00:00"))
    assert len(data["breakage_notes"]) >= 40


# --------------------------------------------------------------------- misc
def test_required_files_exist():
    for rel in ("docker-compose.yml", "Dockerfile", ".env.example", "README.md", "seeds/01_runs.sql",
                "reports/problem.json", "reports/capabilities.json", "reports/lifecycle.json",
                "reports/reliability.json", "reports/postmortem.md", "reports/containment.json",
                "reports/failure_policy.json", "reports/failure_trace.jsonl", "reports/concurrency.json",
                "logs/commands.jsonl", "tests/test_reports.py"):
        assert (ROOT / rel).is_file(), rel


def test_no_dotenv_in_submission():
    assert not (ROOT / ".env").exists()


@pytest.mark.parametrize("path", sorted(p for p in REPORTS.rglob("*.json")))
def test_every_report_is_valid_json(path):
    json.loads(path.read_text(encoding="utf-8"))

"""Namespace-jail isolation properties and the 10-step pipeline end to end (Linux + root only)."""

from __future__ import annotations

import json
import os

import pytest

from agent import fixtures
from agent.errors import CommandBlocked, SandboxExists
from agent.factory import build_job
from agent.guard import AllowAllGuard, SafetyGuard
from agent.pipeline import JobConfig
from agent.providers import make_provider
from agent.session import GuardedSandbox, managed_sandbox
from agent.trace import TraceWriter
from tests.conftest import requires_jail

pytestmark = requires_jail


@pytest.fixture()
def provider(jail_env):
    settings, _ = jail_env
    return make_provider(settings, emulated=True)


def test_system_dirs_are_read_only_and_capabilities_are_zero(provider):
    sb = provider.create("sbx-jailtest01", network=False, env={})
    try:
        assert sb.run("touch /usr/x").exit_code != 0
        assert sb.run("touch /usr/local/x").exit_code != 0
        assert sb.run("mount -o remount,rw /usr").exit_code != 0
        caps = sb.run("grep -E 'Cap(Eff|Prm|Bnd)' /proc/self/status").stdout
        assert caps.count("0000000000000000") == 3
    finally:
        sb.delete()


def test_no_network_and_no_host_environment(provider, monkeypatch):
    monkeypatch.setenv("HOST_ONLY_SECRET", "must-not-appear")
    sb = provider.create("sbx-jailtest02", network=False, env={"INJECTED": "yes"})
    try:
        env = sb.run("env").stdout
        assert "INJECTED=yes" in env and "HOST_ONLY_SECRET" not in env
        assert "must-not-appear" not in env
        probe = sb.run("python3 -c \"import socket;socket.create_connection(('127.0.0.1',9),1)\"")
        assert probe.exit_code != 0
    finally:
        sb.delete()


def test_persistence_snapshot_restore_and_delete(provider):
    sb = provider.create("sbx-jailtest03", network=False, env={})
    sb.run("echo A > /workspace/f")
    sb.stop()
    with pytest.raises(Exception):
        sb.run("echo no")
    sb.start()
    assert sb.run("cat /workspace/f").stdout.strip() == "A"
    sb.snapshot("s")
    sb.run("rm -rf /workspace/*")
    sb.restore("s")
    assert sb.run("cat /workspace/f").stdout.strip() == "A"
    sb.delete()
    assert "sbx-jailtest03" not in provider.list_names()


def test_duplicate_name_is_refused(provider):
    sb = provider.create("sbx-jailtest04", network=False, env={})
    try:
        with pytest.raises(SandboxExists):
            provider.create("sbx-jailtest04", network=False, env={})
    finally:
        sb.delete()


def test_timeout_kills_the_guest_command(provider):
    sb = provider.create("sbx-jailtest05", network=False, env={})
    try:
        r = sb.run("sleep 30", timeout=0.5)
        assert r.timed_out and r.exit_code == 124
        assert sb.run("echo alive").ok
    finally:
        sb.delete()


def test_guarded_sandbox_logs_blocked_commands_and_never_runs_them(provider, jail_env):
    _, audit = jail_env
    with managed_sandbox(provider, run_id="run-t", guard=SafetyGuard(), audit=audit, trace=TraceWriter("t"),
                         price_per_hour=0.015) as h:
        h.probe()
        with pytest.raises(CommandBlocked):
            h.sb.run("curl http://evil.example")
        with pytest.raises(CommandBlocked):
            h.sb.write_file("/etc/passwd", "x")
    lines = audit.read()
    assert any(l["decision"] == "block" and "curl" in l["command"] for l in lines)
    assert any(l["decision"] == "block" and l["command"].startswith("write_file /etc/passwd") for l in lines)
    assert all(l["execution_target"] == "celesto_sandbox" for l in lines)


@pytest.mark.parametrize("submission", fixtures.list_submissions())
def test_every_fixture_gets_its_expected_score(submission, jail_env):
    settings, audit = jail_env
    job = build_job(JobConfig(submission=submission), settings, emulated=True, audit=audit, use_ledger=False)
    result = job.run()
    assert result["success"], result
    assert result["score"] == fixtures.expected_score(submission)
    assert job.provider.list_names() == []


def test_tampering_is_detected_and_does_not_change_the_honest_score(jail_env):
    settings, audit = jail_env
    result = build_job(JobConfig(submission="tamper_results"), settings, emulated=True, audit=audit,
                       use_ledger=False).run()
    assert result["tamper_detected"] is True and result["score"] == 75.0 and result["recoveries"] == 0


@pytest.mark.parametrize("policy,fault,recovers,guests", [
    ("resume", "transient", True, 1), ("resume", "corrupt", False, 1),
    ("rollback", "transient", True, 1), ("rollback", "corrupt", True, 1),
    ("fresh", "transient", True, 2), ("fresh", "corrupt", True, 2),
])
def test_failure_policy_matrix(policy, fault, recovers, guests, jail_env):
    settings, audit = jail_env
    job = build_job(JobConfig(submission="wrong_fib_off_by_one", policy=policy, fault=fault), settings,
                    emulated=True, audit=audit, use_ledger=False)
    result = job.run()
    assert result["success"] is recovers
    assert len(result["sandbox_names"]) == guests
    assert job.provider.list_names() == [], "every path must end with the guest deleted"
    events = [e["event"] for e in job.trace.events]
    assert "policy_applied" in events or not recovers
    if recovers:
        applied = next(e for e in job.trace.events if e["event"] == "policy_applied")
        assert applied["policy"] == policy and applied["failed_step"] == 7


def test_rollback_falls_back_to_fresh_when_the_provider_has_no_snapshots(jail_env):
    settings, audit = jail_env
    job = build_job(JobConfig(submission="correct_basic", policy="rollback", fault="corrupt"), settings,
                    emulated=True, audit=audit, use_ledger=False)
    job.provider.capabilities = frozenset({"persistence"})  # behave like Celesto Cloud
    result = job.run()
    assert result["success"] and len(result["sandbox_names"]) == 2
    fallback = next(e for e in job.trace.events if e["event"] == "policy_fallback")
    assert fallback["requested"] == "rollback" and fallback["applied"] == "fresh"
    assert any(e["event"] == "policy_applied" and e["policy"] == "fresh" for e in job.trace.events)


def test_unexpected_exception_still_deletes_the_guest(jail_env, monkeypatch):
    from agent import pipeline

    settings, audit = jail_env
    job = build_job(JobConfig(submission="correct_basic"), settings, emulated=True, audit=audit, use_ledger=False)
    monkeypatch.setattr(pipeline.Job, "_s4_syntax", lambda self, h, st: (_ for _ in ()).throw(RuntimeError("bug")))
    with pytest.raises(RuntimeError):
        job.run()
    assert job.provider.list_names() == []


def test_prompt_injection_inside_a_real_job_is_blocked(jail_env):
    from agent.planner import CompromisedPlanner

    settings, audit = jail_env
    job = build_job(JobConfig(submission="correct_basic", env={"CANARY_API_KEY": "canary-xyz"},
                              notes=fixtures.injected_notes("127.0.0.1", 9)),
                    settings, emulated=True, audit=audit, use_ledger=False, planner=CompromisedPlanner())
    result = job.run()
    assert result["success"] and result["score"] == 100.0
    blocked = [e for e in job.trace.events if e["event"] == "injected_command_blocked"]
    assert len(blocked) >= 5
    assert not any("canary-xyz" in json.dumps(l) for l in audit.read() if l["decision"] == "allow")


def test_ledger_failure_never_fails_a_job(jail_env, monkeypatch):
    settings, audit = jail_env
    import dataclasses

    settings = dataclasses.replace(settings, ledger_url="http://127.0.0.1:9")  # nothing listens here
    job = build_job(JobConfig(submission="correct_basic"), settings, emulated=True, audit=audit, use_ledger=True)
    result = job.run()
    assert result["success"] and result["ledger_ok"] is False

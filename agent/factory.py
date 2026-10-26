"""Builds a fully wired Job from environment settings (shared by the CLI, the API and the scripts)."""

from __future__ import annotations

from pathlib import Path

from agent.audit import CommandAudit
from agent.config import Settings
from agent.guard import SafetyGuard
from agent.ledger_client import LedgerClient
from agent.pipeline import Job, JobConfig
from agent.planner import Planner, make_planner
from agent.providers import make_provider
from agent.trace import TraceWriter


def build_job(
    cfg: JobConfig,
    settings: Settings | None = None,
    *,
    emulated: bool | None = None,
    guard: SafetyGuard | None = None,
    planner: Planner | None = None,
    audit: CommandAudit | None = None,
    trace_path: Path | None = None,
    use_ledger: bool = True,
    provider=None,
) -> Job:
    settings = settings or Settings.from_env()
    cfg.hidden_timeout_s = settings.hidden_test_timeout_s  # HIDDEN_TEST_TIMEOUT_S
    guard = guard or SafetyGuard()
    provider = provider or make_provider(settings, emulated=emulated, guard=guard)
    audit = audit or CommandAudit(settings.logs_dir / "commands.jsonl")
    ledger = LedgerClient(settings.ledger_url if use_ledger else None)
    job = Job(
        cfg,
        provider=provider,
        guard=guard,
        audit=audit,
        planner=planner or make_planner(settings),
        ledger=ledger,
        price_per_hour=settings.price_per_hour,
    )
    if trace_path:
        job.trace = TraceWriter(job.run_id, trace_path)
    return job

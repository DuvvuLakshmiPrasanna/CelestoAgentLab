"""Command line: ``python -m agent.cli <command>``.

run     grade one submission in a fresh sandbox; Ctrl-C / SIGTERM delete the guest (exit 130)
reap    delete any leftover sbx-* sandboxes this provider knows about
doctor  report which provider can run on this machine and why

The graded reports are produced by ``python -m scripts.generate_reports``.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from agent import fixtures
from agent.config import Settings
from agent.errors import ProviderUnavailable
from agent.factory import build_job
from agent.guard import SafetyGuard
from agent.pipeline import POLICIES, JobConfig
from agent.providers import describe_provider, make_provider
from agent.providers.emulated import availability
from agent.session import install_signal_handlers

EXIT_INTERRUPTED = 130


def _unavailable(exc: Exception) -> int:
    print(f"provider unavailable: {exc}\n"
          "  * EMULATE_CELESTO=1 uses the Linux namespace-jail stand-in (needs Linux and root)\n"
          "  * CELESTO_PROVIDER=local needs Linux+KVM or macOS and `pip install celesto`\n"
          "  * CELESTO_PROVIDER=cloud needs a real CELESTO_API_KEY", file=sys.stderr)
    return 2


def cmd_run(args: argparse.Namespace) -> int:
    settings = Settings.from_env()
    install_signal_handlers()
    notes = fixtures.injected_notes("127.0.0.1", 9) if args.injected else fixtures.BENIGN_NOTES
    cfg = JobConfig(submission=args.submission, policy=args.policy, fault=args.fault, notes=notes,
                    hold_seconds=args.hold_seconds, env={"CANARY_API_KEY": "canary-demo"} if args.injected else {})
    try:
        job = build_job(cfg, settings, use_ledger=not args.no_ledger)
    except ProviderUnavailable as exc:
        return _unavailable(exc)
    try:
        result = job.run()
    except KeyboardInterrupt:
        print(json.dumps({"interrupted": True, "sandboxes": job.sandbox_names,
                          "still_live": [n for n in job.provider.list_names() if n in job.sandbox_names]}))
        return EXIT_INTERRUPTED
    if args.verbose:
        print(json.dumps(result, indent=2))
    print(json.dumps({"run_id": result["run_id"], "submission": result["submission"], "success": result["success"],
                      "score": result["score"], "expected_score": result["expected_score"],
                      "recoveries": result["recoveries"], "tamper_detected": result["tamper_detected"],
                      "wall_clock_s": result["wall_clock_s"], "sandboxes": result["sandbox_names"],
                      "all_deleted": result["all_deleted"], "provider": result["provider"]}))
    return 0 if result["success"] else 1


def cmd_reap(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    try:
        provider = make_provider(settings, guard=SafetyGuard())
    except ProviderUnavailable as exc:
        return _unavailable(exc)
    names = provider.list_names()
    for name in names:
        provider.delete_by_name(name)
    print(f"deleted {len(names)} sandbox(es): {names}")
    return 0


def cmd_doctor(_: argparse.Namespace) -> int:
    settings = Settings.from_env()
    ok, why = availability()
    report = {
        "selected_provider": describe_provider(settings),
        "emulator_available": ok, "emulator_note": why,
        "celesto_provider_env": settings.celesto_provider,
        "celesto_key_is_real": settings.celesto_key_present,
        "llm_configured": settings.llm_enabled,
        "kvm_present": os.path.exists("/dev/kvm"),
    }
    print(json.dumps(report, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agent.cli", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run", help="grade one submission")
    r.add_argument("--submission", default="correct_basic", choices=fixtures.list_submissions())
    r.add_argument("--policy", default="rollback", choices=POLICIES)
    r.add_argument("--fault", default=None, choices=["transient", "corrupt"])
    r.add_argument("--injected", action="store_true", help="use the prompt-injected student notes")
    r.add_argument("--no-ledger", action="store_true", help="do not post run states to the ledger API")
    r.add_argument("--hold-seconds", type=float, default=0.0, help="keep the guest busy (interrupt testing)")
    r.add_argument("--verbose", action="store_true")
    sub.add_parser("reap")
    sub.add_parser("doctor")
    args = ap.parse_args(argv)
    return {"run": cmd_run, "reap": cmd_reap, "doctor": cmd_doctor}[args.command](args)


if __name__ == "__main__":
    sys.exit(main())

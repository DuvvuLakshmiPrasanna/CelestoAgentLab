"""Shared helpers for the experiment scripts that generate reports/ and logs/."""

from __future__ import annotations

import dataclasses
import json
import os
import platform
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "reports"
EVIDENCE = REPORTS / "evidence"
LOGS = ROOT / "logs"

sys.path.insert(0, str(ROOT))

from agent.audit import CommandAudit  # noqa: E402
from agent.config import Settings  # noqa: E402
from agent.guard import SafetyGuard  # noqa: E402
from agent.providers import make_provider  # noqa: E402


@dataclass
class Ctx:
    settings: Settings
    audit: CommandAudit
    provider: Any
    provider_name: str
    ledger_url: str | None
    guard: SafetyGuard


def make_ctx(ledger_url: str | None) -> Ctx:
    settings = Settings.from_env()
    settings = dataclasses.replace(
        settings, emulate_celesto=True, logs_dir=LOGS, reports_dir=REPORTS,
        ledger_url=ledger_url or settings.ledger_url,
    )
    provider = make_provider(settings, emulated=True)
    return Ctx(settings, CommandAudit(LOGS / "commands.jsonl"), provider, provider.name,
               ledger_url, SafetyGuard())


def write_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def rel(path: Path) -> str:
    return str(path.resolve().relative_to(ROOT))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def environment_info() -> dict[str, Any]:
    return {
        "python": platform.python_version(),
        "kernel": platform.release(),
        "cpus": os.cpu_count(),
        "machine": platform.machine(),
        "provider": "emulated-namespace-jail",
        "celesto_sdk_live": False,
        "note": ("Measured on a Linux namespace jail, NOT on Celesto microVMs: the build "
                 "environment had no KVM and no Celesto API key. Re-generate on real Celesto "
                 "with CELESTO_PROVIDER=local|cloud before quoting these as Celesto numbers."),
    }


def reset_outputs() -> None:
    for sub in ("evidence",):
        shutil.rmtree(REPORTS / sub, ignore_errors=True)
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    LOGS.mkdir(parents=True, exist_ok=True)
    (LOGS / "commands.jsonl").write_text("", encoding="utf-8")

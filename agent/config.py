"""Settings, read from the environment. Every variable read anywhere in the
project is documented in ``.env.example`` (a test enforces this)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def is_placeholder(value: str) -> bool:
    v = (value or "").strip().lower()
    return v == "" or v.startswith("replace-") or v in {"changeme", "your-api-key"}


def _flag(name: str, default: str = "0") -> bool:
    return os.environ.get(name, default).strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    celesto_provider: str
    celesto_api_key: str
    celesto_backend: str
    emulate_celesto: bool
    llm_base_url: str
    llm_api_key: str
    llm_model: str
    database_url: str
    api_port: int
    ledger_url: str
    price_per_hour: float
    failure_policy: str
    emulator_home: Path
    reports_dir: Path
    logs_dir: Path
    hidden_test_timeout_s: float
    guest_memory_limit_mb: int
    guest_cpu_limit_s: int
    max_concurrent_jobs: int

    @classmethod
    def from_env(cls) -> "Settings":
        api_port = int(os.environ.get("API_PORT", "8080"))
        return cls(
            celesto_provider=os.environ.get("CELESTO_PROVIDER", "cloud").strip().lower(),
            celesto_api_key=os.environ.get("CELESTO_API_KEY", "replace-me"),
            celesto_backend=os.environ.get("CELESTO_BACKEND", "firecracker"),
            emulate_celesto=_flag("EMULATE_CELESTO"),
            llm_base_url=os.environ.get("LLM_BASE_URL", "https://example-llm-host/v1"),
            llm_api_key=os.environ.get("LLM_API_KEY", "replace-me"),
            llm_model=os.environ.get("LLM_MODEL", "replace-with-a-model-name"),
            database_url=os.environ.get(
                "DATABASE_URL", "postgresql://ledger:ledger@localhost:5432/ledger"
            ),
            api_port=api_port,
            ledger_url=os.environ.get("LEDGER_URL", f"http://localhost:{api_port}"),
            price_per_hour=float(os.environ.get("SANDBOX_PRICE_PER_HOUR", "0.015")),
            failure_policy=os.environ.get("FAILURE_POLICY", "rollback").strip().lower(),
            emulator_home=Path(
                os.environ.get("EMULATOR_HOME", str(ROOT / ".sandbox-emulator"))
            ).resolve(),
            reports_dir=Path(os.environ.get("REPORTS_DIR", str(ROOT / "reports"))).resolve(),
            logs_dir=Path(os.environ.get("LOGS_DIR", str(ROOT / "logs"))).resolve(),
            hidden_test_timeout_s=float(os.environ.get("HIDDEN_TEST_TIMEOUT_S", "3")),
            guest_memory_limit_mb=int(os.environ.get("GUEST_MEMORY_LIMIT_MB", "1024")),
            guest_cpu_limit_s=int(os.environ.get("GUEST_CPU_LIMIT_S", "30")),
            max_concurrent_jobs=int(os.environ.get("MAX_CONCURRENT_JOBS", "2")),
        )

    @property
    def llm_enabled(self) -> bool:
        return not is_placeholder(self.llm_api_key) and not is_placeholder(self.llm_model)

    @property
    def celesto_key_present(self) -> bool:
        return not is_placeholder(self.celesto_api_key)

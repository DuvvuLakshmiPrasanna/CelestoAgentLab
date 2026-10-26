"""docker-compose.yml, Dockerfile, .env.example and seeds: the control-plane contract."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
REQUIRED_KEYS = ["CELESTO_PROVIDER", "CELESTO_API_KEY", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL", "API_PORT"]


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text())


def test_services_exist(compose):
    assert {"api", "ledger"} <= set(compose["services"])


@pytest.mark.parametrize("service", ["api", "ledger"])
def test_healthcheck_has_all_timing_fields(compose, service):
    hc = compose["services"][service]["healthcheck"]
    for field in ("test", "interval", "timeout", "retries", "start_period"):
        assert field in hc, f"{service} healthcheck is missing {field}"


def test_ledger_uses_pg_isready_and_mounts_seeds(compose):
    ledger = compose["services"]["ledger"]
    assert "pg_isready" in " ".join(ledger["healthcheck"]["test"])
    assert any(v.startswith("./seeds:") for v in ledger["volumes"])


def test_api_waits_for_healthy_ledger_and_publishes_8080(compose):
    api = compose["services"]["api"]
    assert api["depends_on"]["ledger"]["condition"] == "service_healthy"
    assert any(str(p).endswith(":8080") for p in api["ports"])
    assert "curl" in " ".join(api["healthcheck"]["test"]) and "localhost:8080/health" in " ".join(api["healthcheck"]["test"])
    assert api["build"]["dockerfile"] == "Dockerfile"


def test_no_firecracker_service(compose):
    assert not any("firecracker" in name.lower() for name in compose["services"])


def test_healthy_within_five_minutes(compose):
    """Worst-case time to healthy = start_period + interval*retries per service must be < 300s."""
    def secs(v):
        m = re.fullmatch(r"(\d+)(ms|s|m)", str(v))
        n, unit = int(m.group(1)), m.group(2)
        return n * {"ms": 0.001, "s": 1, "m": 60}[unit]

    total = 0
    for svc in ("ledger", "api"):
        hc = compose["services"][svc]["healthcheck"]
        total += secs(hc["start_period"]) + secs(hc["interval"]) * hc["retries"]
    assert total < 300, total


def test_env_example_has_required_keys_and_placeholders():
    text = (ROOT / ".env.example").read_text()
    values = dict(line.split("=", 1) for line in text.splitlines() if line and not line.startswith("#"))
    for key in REQUIRED_KEYS:
        assert key in values, key
    assert values["CELESTO_API_KEY"] == "replace-me" and values["LLM_API_KEY"] == "replace-me"
    assert values["CELESTO_PROVIDER"] in ("local", "cloud")


def test_every_env_var_the_code_reads_is_documented():
    documented = {l.split("=", 1)[0] for l in (ROOT / ".env.example").read_text().splitlines()
                  if l and not l.startswith("#")}
    read = set()
    for path in list((ROOT / "agent").rglob("*.py")) + list((ROOT / "app").rglob("*.py")):
        src = path.read_text()
        read |= set(re.findall(r'environ\.get\(\s*"([A-Z][A-Z0-9_]+)"', src))
        read |= set(re.findall(r'environ\[\s*"([A-Z][A-Z0-9_]+)"\s*\]', src))
        read |= set(re.findall(r'_flag\(\s*"([A-Z][A-Z0-9_]+)"', src))
    assert read, "scan found nothing: the regexes are broken"
    assert not (read - documented), f"undocumented variables: {sorted(read - documented)}"


def test_no_dotenv_and_no_live_secrets():
    assert not (ROOT / ".env").exists()
    patterns = [r"AKIA[0-9A-Z]{16}", r"gh[pousr]_[A-Za-z0-9]{30,}", r"sk-[A-Za-z0-9]{20,}",
                r"-----BEGIN [A-Z ]*PRIVATE KEY-----", r"xox[baprs]-[A-Za-z0-9-]{10,}"]
    offenders = []
    for path in ROOT.rglob("*"):
        if not path.is_file() or ".sandbox-emulator" in path.parts or path.suffix in {".mp4", ".png", ".zip"}:
            continue
        if path.name == "test_compose.py":
            continue
        text = path.read_text(errors="ignore")
        for pat in patterns:
            if re.search(pat, text):
                offenders.append((str(path.relative_to(ROOT)), pat))
    assert not offenders, offenders


def test_seed_sql_is_idempotent_and_uses_spec_values():
    sql = (ROOT / "seeds" / "01_runs.sql").read_text()
    assert "sbx-seeddemo1" in sql and "'deleted'" in sql and "celesto_sandbox" in sql
    assert "ON CONFLICT" in sql.upper()
    assert "CREATE TABLE IF NOT EXISTS" in sql.upper()


def test_dockerfile_basics():
    text = (ROOT / "Dockerfile").read_text()
    assert "curl" in text, "the healthcheck needs curl inside the image"
    assert "EXPOSE 8080" in text
    assert "USER " in text, "the API must not run as root"

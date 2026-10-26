"""Request validation for POST /api/runs.

FastAPI's built-in body validation answers 422. The ledger contract says an
invalid execution_target, state or sandbox_name must answer 400, so validation
is done by hand on the raw JSON object.
"""

from __future__ import annotations

from typing import Any

from app.db import EXECUTION_TARGET, SANDBOX_NAME_RE, VALID_STATES

REQUIRED_FIELDS = ("run_id", "sandbox_name", "problem_id", "state", "execution_target")
_MAX_LEN = 200


class ValidationFailure(ValueError):
    def __init__(self, field: str, message: str) -> None:
        super().__init__(message)
        self.field = field
        self.message = message


def _clean_text(payload: dict[str, Any], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise ValidationFailure(field, f"{field} must be a non-empty string")
    if len(value) > _MAX_LEN or any(ord(ch) < 32 for ch in value):
        raise ValidationFailure(field, f"{field} is too long or contains control characters")
    return value.strip()


def validate_run(payload: Any) -> dict[str, str]:
    """Return a clean run dict or raise :class:`ValidationFailure`."""
    if not isinstance(payload, dict):
        raise ValidationFailure("body", "request body must be a JSON object")

    for field in REQUIRED_FIELDS:
        if field not in payload:
            raise ValidationFailure(field, f"missing required field: {field}")

    run_id = _clean_text(payload, "run_id")
    problem_id = _clean_text(payload, "problem_id")

    sandbox_name = payload.get("sandbox_name")
    if not isinstance(sandbox_name, str) or SANDBOX_NAME_RE.fullmatch(sandbox_name) is None:
        raise ValidationFailure(
            "sandbox_name",
            "sandbox_name must be 'sbx-' followed by 8 or more lowercase letters or digits",
        )

    state = payload.get("state")
    if not isinstance(state, str) or state not in VALID_STATES:
        raise ValidationFailure("state", f"state must be one of: {', '.join(VALID_STATES)}")

    target = payload.get("execution_target")
    if target != EXECUTION_TARGET:
        raise ValidationFailure(
            "execution_target",
            f"execution_target must be '{EXECUTION_TARGET}'; tools never run on the host",
        )

    return {
        "run_id": run_id,
        "sandbox_name": sandbox_name,
        "problem_id": problem_id,
        "state": state,
        "execution_target": target,
    }

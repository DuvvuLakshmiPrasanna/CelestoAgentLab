"""Posts run-state rows to the ledger API. Failure to reach the ledger is never
fatal to a run: the audit log and trace are the source of truth for the run itself,
and the client reports whether the ledger was reachable."""

from __future__ import annotations

import logging

import httpx

from agent.audit import EXECUTION_TARGET

log = logging.getLogger("ledger-client")


class LedgerClient:
    def __init__(self, base_url: str | None, timeout_s: float = 3.0) -> None:
        self.base_url = (base_url or "").rstrip("/") or None
        # trust_env=False: the ledger is an internal service; never route it through an HTTP proxy.
        self._client = httpx.Client(timeout=timeout_s, trust_env=False) if self.base_url else None
        self.ok = True
        self.last_error: str | None = None
        self.posts = 0

    @property
    def enabled(self) -> bool:
        return self._client is not None

    def post_state(self, run_id: str, sandbox_name: str, problem_id: str, state: str) -> bool:
        if not self._client:
            return False
        body = {
            "run_id": run_id,
            "sandbox_name": sandbox_name,
            "problem_id": problem_id,
            "state": state,
            "execution_target": EXECUTION_TARGET,
        }
        try:
            resp = self._client.post(f"{self.base_url}/api/runs", json=body)
            if resp.status_code != 201:
                raise RuntimeError(f"ledger answered {resp.status_code}: {resp.text[:120]}")
            self.posts += 1
            return True
        except Exception as exc:  # noqa: BLE001
            self.ok = False
            self.last_error = str(exc)[:200]
            log.warning("ledger unavailable (%s); continuing without it", self.last_error)
            return False

    def close(self) -> None:
        if self._client:
            self._client.close()

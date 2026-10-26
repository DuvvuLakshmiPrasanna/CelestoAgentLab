"""Sandbox lifecycle and the guarded execution boundary.

Two things live here because they must never be separated:

``GuardedSandbox``
    The ONLY object the agent loop is handed. Every call goes
    hook -> audit line -> sandbox. A blocked command raises ``CommandBlocked`` and
    still produces an audit line. There is no method that runs anything on the host.

``managed_sandbox``
    create -> yield -> ALWAYS delete. The ``finally`` clause runs on success,
    on any exception (including ``StepFailed``) and on Ctrl-C / SIGTERM
    (``KeyboardInterrupt``). A process-wide registry plus an ``atexit`` hook is
    the second line of defence against orphans, and ``python -m agent.cli reap``
    is the third.
"""

from __future__ import annotations

import atexit
import hashlib
import signal
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Iterator

from agent.audit import CommandAudit
from agent.errors import CommandBlocked, SandboxError
from agent.guard import SafetyGuard
from agent.naming import new_sandbox_name
from agent.providers.base import ExecResult, Provider, Sandbox, read_file, write_file
from agent.trace import TraceWriter

WRITABLE_PREFIXES = ("/workspace/", "/tmp/", "/root/")


class GuardedSandbox:
    """hook -> audit -> sandbox. The agent never sees the raw provider object."""

    def __init__(
        self,
        raw: Sandbox,
        guard: SafetyGuard,
        audit: CommandAudit,
        *,
        run_id: str,
    ) -> None:
        self._raw = raw
        self._guard = guard
        self._audit = audit
        self.run_id = run_id
        self.step: int | None = None

    @property
    def name(self) -> str:
        return self._raw.name

    @property
    def provider(self) -> str:
        return self._raw.provider

    def _log(self, command: str, decision: str, **extra: object) -> None:
        self._audit.append(
            self.name,
            command,
            decision,
            provider=self.provider,
            run_id=self.run_id,
            step=self.step,
            **extra,
        )

    # ------------------------------------------------------------- commands
    def run(self, command: str, timeout: float = 30.0, actor: str = "agent") -> ExecResult:
        verdict = self._guard.check(command)
        if not verdict.allowed:
            self._log(command, "block", rule=verdict.rule, reason=verdict.reason, actor=actor)
            raise CommandBlocked(command, verdict.rule, verdict.reason)
        self._log(command, "allow", actor=actor)
        return self._raw.run(command, timeout=timeout)

    def write_file(self, path: str, data: bytes | str) -> None:
        raw = data.encode("utf-8") if isinstance(data, str) else data
        digest = hashlib.sha256(raw).hexdigest()[:16]
        label = f"write_file {path} ({len(raw)} bytes, sha256={digest})"
        if not path.startswith(WRITABLE_PREFIXES) or ".." in path:
            self._log(label, "block", rule="write_outside_workspace",
                      reason="files may only be written under /workspace, /tmp or /root",
                      actor="agent")
            raise CommandBlocked(label, "write_outside_workspace",
                                 "files may only be written under /workspace, /tmp or /root")
        self._log(label, "allow", actor="agent")
        write_file(self._raw, path, raw)

    def read_file(self, path: str) -> bytes:
        self._log(f"read_file {path}", "allow", actor="agent")
        return read_file(self._raw, path)

    # ------------------------------------------------------------ lifecycle
    def snapshot(self, snapshot_id: str) -> None:
        self._log(f"celesto snapshot {snapshot_id}", "allow", actor="lifecycle")
        self._raw.snapshot(snapshot_id)

    def restore(self, snapshot_id: str) -> None:
        self._log(f"celesto restore {snapshot_id}", "allow", actor="lifecycle")
        self._raw.restore(snapshot_id)

    def stop(self) -> None:
        self._log("celesto stop", "allow", actor="lifecycle")
        self._raw.stop()

    def start(self) -> None:
        self._log("celesto start", "allow", actor="lifecycle")
        self._raw.start()

    def chaos(self, command: str, timeout: float = 30.0) -> ExecResult:
        """Fault injection used by the failure tests. Audited, never agent-driven."""
        self._log(command, "allow", actor="chaos")
        return self._raw.run(command, timeout=timeout)

    def delete(self) -> None:
        self._log("celesto delete", "allow", actor="lifecycle")
        self._raw.delete()


class CleanupRegistry:
    """Sandboxes that exist right now. Emptied by the normal ``finally`` path;
    anything left at interpreter exit is deleted by ``cleanup_all``."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._live: dict[str, Provider] = {}

    def add(self, name: str, provider: Provider) -> None:
        with self._lock:
            self._live[name] = provider

    def discard(self, name: str) -> None:
        with self._lock:
            self._live.pop(name, None)

    def live(self) -> list[str]:
        with self._lock:
            return sorted(self._live)

    def cleanup_all(self) -> list[str]:
        with self._lock:
            items = list(self._live.items())
            self._live.clear()
        cleaned: list[str] = []
        for name, provider in items:
            try:
                provider.delete_by_name(name)
                cleaned.append(name)
            except Exception:  # pragma: no cover - best effort at exit
                pass
        return cleaned


REGISTRY = CleanupRegistry()
atexit.register(REGISTRY.cleanup_all)


def install_signal_handlers() -> None:
    """Turn SIGINT/SIGTERM/SIGHUP into KeyboardInterrupt so ``finally`` blocks run.

    SIGINT is installed explicitly, not left to Python's default: a process started from a
    background shell job, ``nohup``, cron or many CI runners inherits SIGINT as *ignored*,
    and Python then never installs its own Ctrl-C handler (observed: an "interrupted" job
    ran to completion and exited 0). Must be called from the main thread.
    """

    def _raise(signum: int, _frame: object) -> None:
        raise KeyboardInterrupt(f"signal {signum}")

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        try:
            signal.signal(sig, _raise)
        except (ValueError, OSError):  # not the main thread / unsupported platform
            pass


@dataclass
class SandboxHandle:
    sb: GuardedSandbox
    name: str
    provider: Provider
    price_per_hour: float
    trace: TraceWriter
    audit: CommandAudit
    create_started: float
    boot_to_ready_s: float = 0.0
    deleted: bool = False
    deleted_at: float = 0.0
    cleanup_error: str | None = None

    def probe(self, timeout: float = 30.0) -> float:
        """Boot probe. ``boot_to_ready_s`` is create-start to this probe passing."""
        result = self.sb.run("echo ready", timeout=timeout, actor="lifecycle")
        if not result.ok or result.stdout.strip() != "ready":
            raise SandboxError(f"boot probe failed: rc={result.exit_code} {result.stderr[:120]}")
        self.boot_to_ready_s = time.perf_counter() - self.create_started
        return self.boot_to_ready_s

    def close(self) -> None:
        """Idempotent: delete the sandbox, retrying a few times, never raising."""
        if self.deleted:
            return
        error: Exception | None = None
        for attempt in range(3):
            try:
                self.sb.delete()
                error = None
                break
            except Exception as exc:  # noqa: BLE001 - cleanup must never mask the real error
                error = exc
                try:
                    self.provider.delete_by_name(self.name)
                    error = None
                    break
                except Exception as exc2:  # noqa: BLE001
                    error = exc2
                time.sleep(0.3 * (attempt + 1))
        self.deleted = error is None
        self.deleted_at = time.perf_counter()
        self.cleanup_error = None if error is None else str(error)[:200]
        REGISTRY.discard(self.name)
        self.trace.event(
            "sandbox_deleted" if error is None else "sandbox_delete_failed",
            sandbox_name=self.name,
            error=self.cleanup_error,
        )

    def billed_seconds(self) -> float:
        end = self.deleted_at if self.deleted_at else time.perf_counter()
        return max(0.0, end - self.create_started)

    def cost_usd(self) -> float:
        return self.billed_seconds() / 3600.0 * self.price_per_hour


@contextmanager
def managed_sandbox(
    provider: Provider,
    *,
    run_id: str,
    guard: SafetyGuard,
    audit: CommandAudit,
    trace: TraceWriter,
    price_per_hour: float,
    network: bool = False,
    env: dict[str, str] | None = None,
) -> Iterator[SandboxHandle]:
    """create -> yield -> always delete (success, failure, Ctrl-C)."""
    name = new_sandbox_name()
    REGISTRY.add(name, provider)  # registered BEFORE creation so an interrupt mid-create is cleaned
    started = time.perf_counter()
    handle: SandboxHandle | None = None
    try:
        raw = provider.create(name, network=network, env=env or {})
        trace.event("sandbox_created", sandbox_name=name, provider=raw.provider,
                    provider_id=raw.provider_id, network=network)
        handle = SandboxHandle(
            sb=GuardedSandbox(raw, guard, audit, run_id=run_id),
            name=name,
            provider=provider,
            price_per_hour=price_per_hour,
            trace=trace,
            audit=audit,
            create_started=started,
        )
        yield handle
    finally:
        if handle is not None:
            handle.close()
        else:  # creation itself failed or was interrupted: remove whatever half-exists
            try:
                provider.delete_by_name(name)
            except Exception:  # noqa: BLE001
                pass
            REGISTRY.discard(name)

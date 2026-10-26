"""Real Celesto computers through the official SDK (``pip install celesto``).

Two modes, selected by ``CELESTO_PROVIDER``:

``cloud``  ``celesto.Computer(provider="cloud", lifetime="persistent")``.
           Needs ``CELESTO_API_KEY``. Persistence (stop/start) is available.
           Snapshots and network policy are local-runtime features per the
           Celesto docs, so this mode advertises neither; the pipeline then
           falls back from ``rollback`` to ``fresh`` and says so in the trace.
``local``  ``celesto.Celesto(...)``, the open-source microVM runtime
           (Linux + KVM with Firecracker, or macOS with QEMU). Snapshots,
           ``internet_settings={"mode": "off"}`` and SDK callbacks are all
           available.

The SDK is imported lazily so the API container and the tests run without it.

NOTE ON VERIFICATION: this module is written against celesto 0.1.8 (the
signatures were read from the installed package) and exercised in
``tests/test_celesto_provider.py`` against a recording fake of the SDK. It was
NOT run against a live Celesto service in the environment that built this
repository, because that environment had neither KVM nor a Celesto API key.
"""

from __future__ import annotations

import shlex
import threading
import time
from typing import Any

from agent.config import Settings
from agent.errors import ProviderUnavailable, SandboxError, SandboxExists
from agent.guard import SafetyGuard
from agent.providers.base import ExecResult

PROVIDER_NAME = "celesto"


def _import_sdk() -> Any:
    try:
        import celesto  # type: ignore
    except Exception as exc:  # ImportError or a broken optional dependency
        raise ProviderUnavailable(
            "the celesto SDK is not installed (pip install -r requirements-celesto.txt)"
        ) from exc
    return celesto


def _env_prefix(env: dict[str, str]) -> str:
    return "".join(f"export {k}={shlex.quote(v)}; " for k, v in env.items())


class CelestoSandbox:
    def __init__(
        self,
        name: str,
        mode: str,
        handle: Any,
        env: dict[str, str],
        sdk: Any,
        network: bool,
        backend: str | None,
    ) -> None:
        self.name = name  # our collision-proof alias; Celesto cloud assigns its own name
        self.provider = f"celesto-{mode}"
        self.provider_id = str(getattr(handle, "id", None) or getattr(handle, "vm_id", None) or name)
        self._mode = mode
        self._h = handle
        self._env_prefix = _env_prefix(env)
        self._sdk = sdk
        self._network = network
        self._backend = backend
        self._deleted = False

    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        started = time.perf_counter()
        try:
            res = self._h.run(self._env_prefix + command, timeout=max(1, int(timeout)))
        except Exception as exc:
            # A CommandBlockedError raised by an SDK callback is a deliberate veto, not a crash:
            # let it propagate untouched. Compare by TYPE, not by class name.
            blocked_type = getattr(self._sdk, "CommandBlockedError", None)
            if isinstance(blocked_type, type) and isinstance(exc, blocked_type):
                raise
            if "timeout" in type(exc).__name__.lower() or "timed out" in str(exc).lower():
                return ExecResult(124, "", str(exc), time.perf_counter() - started, True)
            raise SandboxError(f"celesto run failed: {exc}") from exc
        return ExecResult(
            exit_code=int(res.exit_code),
            stdout=str(res.stdout),
            stderr=str(res.stderr),
            duration_s=time.perf_counter() - started,
        )

    def snapshot(self, snapshot_id: str) -> None:
        if self._mode != "local":
            raise SandboxError("snapshots are a local-runtime feature of Celesto")
        self._h.snapshot(snapshot_id=snapshot_id, resume_source=True)

    def restore(self, snapshot_id: str) -> None:
        if self._mode != "local":
            raise SandboxError("snapshots are a local-runtime feature of Celesto")
        # Documented pattern: stop + delete, then restore the snapshot and resume it.
        try:
            self._h.stop()
            self._h.delete()
        except Exception:
            pass
        self._h = self._sdk.Celesto.from_snapshot(snapshot_id, resume_vm=True, force=True)

    def stop(self) -> None:
        self._h.stop()

    def start(self) -> None:
        self._h.start()

    def delete(self) -> None:
        if self._deleted:
            return
        self._deleted = True
        try:
            if self._mode == "local":
                try:
                    self._h.stop()
                except Exception:
                    pass
            self._h.delete()
        except Exception as exc:
            self._deleted = False
            raise SandboxError(f"celesto delete failed: {exc}") from exc


class CelestoProvider:
    name = PROVIDER_NAME

    def __init__(self, settings: Settings, guard: SafetyGuard | None = None) -> None:
        self._s = settings
        self._mode = settings.celesto_provider
        if self._mode not in ("local", "cloud"):
            raise ProviderUnavailable(
                f"CELESTO_PROVIDER must be 'local' or 'cloud', got '{self._mode}'"
            )
        if self._mode == "cloud" and not settings.celesto_key_present:
            raise ProviderUnavailable(
                "CELESTO_PROVIDER=cloud needs a real CELESTO_API_KEY (still the placeholder)"
            )
        self._sdk = _import_sdk()
        self._guard = guard
        self._names: dict[str, CelestoSandbox] = {}
        self._lock = threading.Lock()
        if self._mode == "local":
            self.capabilities = frozenset({"persistence", "snapshots", "network_policy", "safety_hooks"})
        else:
            self.capabilities = frozenset({"persistence", "safety_hooks"})

    # -- SDK callback so the same guard also runs inside the SDK (defence in depth)
    def _callbacks(self) -> list[Any]:
        guard = self._guard
        if guard is None:
            return []
        sdk = self._sdk

        class GuardCallback(sdk.Callback):  # type: ignore[misc, name-defined]
            def on_pre_run(self, ctx: Any) -> None:
                verdict = guard.check(ctx.command)
                if not verdict.allowed:
                    raise sdk.CommandBlockedError(
                        f"blocked by rule '{verdict.rule}': {verdict.reason}",
                        vm_id=getattr(ctx, "vm_id", None),
                        command=ctx.command,
                    )

        return [GuardCallback()]

    def create(self, name: str, *, network: bool, env: dict[str, str]) -> CelestoSandbox:
        with self._lock:
            if name in self._names:
                raise SandboxExists(f"sandbox {name} already exists")
            sdk = self._sdk
            try:
                if self._mode == "cloud":
                    handle = sdk.Computer(
                        provider="cloud",
                        lifetime="persistent",
                        api_key=self._s.celesto_api_key,
                    )
                    handle.start()
                else:
                    kwargs: dict[str, Any] = {"callbacks": self._callbacks()}
                    if self._s.celesto_backend:
                        kwargs["backend"] = self._s.celesto_backend
                    if not network:
                        kwargs["internet_settings"] = {"mode": "off"}
                    handle = sdk.Celesto(**kwargs)
                    handle.start()
            except Exception as exc:
                raise SandboxError(f"could not create a celesto {self._mode} computer: {exc}") from exc
            sandbox = CelestoSandbox(
                name,
                self._mode,
                handle,
                env,
                sdk,
                network,
                self._s.celesto_backend or None,
            )
            self._names[name] = sandbox
            return sandbox

    def list_names(self) -> list[str]:
        return sorted(self._names)

    def delete_by_name(self, name: str) -> None:
        sandbox = self._names.pop(name, None)
        if sandbox is not None:
            sandbox.delete()

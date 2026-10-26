"""Provider factory."""

from __future__ import annotations

from agent.config import Settings
from agent.errors import ProviderUnavailable
from agent.guard import SafetyGuard
from agent.providers.base import ExecResult, Provider, Sandbox, read_file, write_file

__all__ = [
    "ExecResult",
    "Provider",
    "Sandbox",
    "read_file",
    "write_file",
    "make_provider",
    "describe_provider",
]


def make_provider(
    settings: Settings, *, emulated: bool | None = None, guard: SafetyGuard | None = None
) -> Provider:
    """Return the provider for these settings.

    ``emulated=None`` follows ``EMULATE_CELESTO``. A real Celesto provider that
    cannot start (no key, no KVM, SDK missing) raises ``ProviderUnavailable``
    rather than silently falling back: a reviewer must always know which
    backend produced a number.
    """
    use_emulator = settings.emulate_celesto if emulated is None else emulated
    if use_emulator:
        from agent.providers.emulated import EmulatedProvider

        return EmulatedProvider(
            settings.emulator_home,
            memory_mb=settings.guest_memory_limit_mb,
            cpu_s=settings.guest_cpu_limit_s,
        )
    from agent.providers.celesto_provider import CelestoProvider

    return CelestoProvider(settings, guard=guard)


def describe_provider(settings: Settings, emulated: bool | None = None) -> str:
    use_emulator = settings.emulate_celesto if emulated is None else emulated
    return "emulated-namespace-jail" if use_emulator else f"celesto-{settings.celesto_provider}"

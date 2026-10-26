"""Exception types shared across the harness."""

from __future__ import annotations


class HarnessError(Exception):
    """Base class for harness errors."""


class CommandBlocked(HarnessError):
    """A safety hook refused a command; it never reached the guest."""

    def __init__(self, command: str, rule: str, reason: str) -> None:
        super().__init__(f"blocked by rule '{rule}': {reason}")
        self.command = command
        self.rule = rule
        self.reason = reason


class SandboxError(HarnessError):
    """A provider could not create, reach or operate a sandbox."""


class SandboxExists(SandboxError):
    """A sandbox with this name already exists (name collision)."""


class ProviderUnavailable(SandboxError):
    """The configured provider cannot run here (no key, no KVM, SDK missing)."""


class StepFailed(HarnessError):
    """An agent step did not complete. ``step`` is 1-based."""

    def __init__(self, step: int, name: str, reason: str) -> None:
        super().__init__(f"step {step} ({name}) failed: {reason}")
        self.step = step
        self.name = name
        self.reason = reason

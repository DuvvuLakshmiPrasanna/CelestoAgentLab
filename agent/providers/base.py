"""Provider interface: the only way the harness touches a computer.

Two implementations satisfy it:

* ``CelestoProvider``   real Celesto computers (local Firecracker/QEMU or cloud)
* ``EmulatedProvider``  a Linux-namespace jail used when no KVM / no cloud key is
                        available (CI, review machines, this repo's shipped numbers).

Both expose identical ``Sandbox`` objects, so the guard, audit log, lifecycle
manager and the grading pipeline are the same code in both cases.
"""

from __future__ import annotations

import base64
import shlex
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from agent.errors import SandboxError

_CHUNK_BYTES = 32 * 1024  # base64 payload per command, safely below ARG_MAX


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    duration_s: float = 0.0
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.exit_code == 0 and not self.timed_out


@runtime_checkable
class Sandbox(Protocol):
    name: str
    provider: str
    provider_id: str

    def run(self, command: str, timeout: float = 30.0) -> ExecResult: ...
    def snapshot(self, snapshot_id: str) -> None: ...
    def restore(self, snapshot_id: str) -> None: ...
    def stop(self) -> None: ...
    def start(self) -> None: ...
    def delete(self) -> None: ...


@runtime_checkable
class Provider(Protocol):
    name: str
    #: subset of {"persistence", "snapshots", "network_policy", "safety_hooks"}
    capabilities: frozenset[str]

    def create(self, name: str, *, network: bool, env: dict[str, str]) -> Sandbox: ...
    def list_names(self) -> list[str]: ...
    def delete_by_name(self, name: str) -> None: ...


def write_file(sandbox: Sandbox, path: str, data: bytes | str, timeout: float = 30.0) -> None:
    """Write a file inside the guest using only ``sandbox.run``.

    Routing writes through the guest's own shell means the same code path works
    for every provider and the guard/audit layers see it like any other command.
    """
    raw = data.encode("utf-8") if isinstance(data, str) else data
    quoted = shlex.quote(path)
    first = True
    chunks = [raw[i : i + _CHUNK_BYTES] for i in range(0, len(raw), _CHUNK_BYTES)] or [b""]
    for chunk in chunks:
        payload = base64.b64encode(chunk).decode("ascii")
        redirect = ">" if first else ">>"
        result = sandbox.run(
            f"mkdir -p \"$(dirname {quoted})\" && printf %s {shlex.quote(payload)} | base64 -d {redirect} {quoted}",
            timeout=timeout,
        )
        if not result.ok:
            raise SandboxError(f"write_file {path} failed: {result.stderr.strip()[:200]}")
        first = False


def read_file(sandbox: Sandbox, path: str, timeout: float = 30.0) -> bytes:
    result = sandbox.run(f"base64 -w0 {shlex.quote(path)}", timeout=timeout)
    if not result.ok:
        raise SandboxError(f"read_file {path} failed: {result.stderr.strip()[:200]}")
    return base64.b64decode(result.stdout.strip() or "")

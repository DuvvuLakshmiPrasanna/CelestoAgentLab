"""Namespace-jail stand-in for a Celesto computer.

WHY THIS EXISTS
    Celesto microVMs need KVM (local) or an API key (cloud). Neither exists on a
    reviewer's laptop or in this repo's build environment, yet the project must
    still be demonstrable and measurable. This provider implements the same
    ``Sandbox`` interface with Linux namespaces so the eval, containment and
    failure tests produce REAL measurements of REAL isolation.

WHAT IT IS NOT
    It is not a microVM. The guest shares the host kernel, so a kernel exploit
    could escape it. Every report says ``provider: emulated-namespace-jail`` and
    the README explains which numbers must be regenerated on real Celesto.

WHAT EACH COMMAND GETS
    * its own mount namespace with a tmpfs root; /usr, /bin, /lib* are bind
      mounts that are remounted read-only AND verified read-only before the guest
      starts (a writable system mount aborts the command instead of running it);
    * its own PID namespace (every process dies with the command, --kill-child);
    * its own network namespace unless ``network=True`` (internet off = no
      interfaces at all, the equivalent of Celesto ``internet_settings={"mode":"off"}``);
    * no host environment: ``env -i`` plus only the variables the harness injects;
    * a private persistent disk (``workspace``, ``root``, ``tmp``) that survives
      stop/start and snapshots, like a Celesto root disk;
    * ulimits for memory, CPU seconds and file size;
    * ALL Linux capabilities dropped and no_new_privs set, so root inside the
      guest cannot ``mount -o remount,rw``, ``chroot`` out, or touch devices.
"""

from __future__ import annotations

import os
import platform
import shutil
import signal
import subprocess
import tarfile
import threading
import time
from pathlib import Path

from agent.errors import ProviderUnavailable, SandboxError, SandboxExists
from agent.providers.base import ExecResult

PROVIDER_NAME = "emulated-namespace-jail"
_OUTPUT_CAP = 256 * 1024

JAIL_SCRIPT = r"""#!/bin/bash
# usage: jail.sh ROOT DISK MEM_KB CPU_S FSIZE_KB CMD [VAR=VAL ...]
# Runs inside fresh mount/pid/uts/ipc(/net) namespaces created by `unshare`.
ROOT=$1; DISK=$2; MEM=$3; CPU=$4; FSZ=$5; CMD=$6
shift 6

fail() { echo "jail: $*" >&2; exit 111; }

mount --make-rprivate / 2>/dev/null || fail "cannot make mounts private"
mount -t tmpfs -o size=64m,mode=755 tmpfs "$ROOT" || fail "cannot mount tmpfs root"

for d in usr bin sbin lib lib32 lib64 libx32; do
  if [ -L "/$d" ]; then
    ln -s "$(readlink "/$d")" "$ROOT/$d"
  elif [ -d "/$d" ]; then
    mkdir -p "$ROOT/$d"
    mount --rbind "/$d" "$ROOT/$d" || fail "cannot bind /$d"
  fi
done

# Every system mount (including nested ones such as /usr/local) becomes read-only.
while read -r mp; do
  mount -o remount,bind,ro "$mp" 2>/dev/null || mount -o remount,ro "$mp" 2>/dev/null \
    || fail "cannot remount $mp read-only"
done < <(awk -v r="$ROOT/" 'index($5, r) == 1 { print $5 }' /proc/self/mountinfo)

# Verify, do not assume: refuse to run if ANY system mount is still writable.
while read -r mp; do
  if ( : > "$mp/.jail-rw-probe" ) 2>/dev/null; then
    rm -f "$mp/.jail-rw-probe"
    fail "system mount $mp is writable; refusing to run"
  fi
done < <(awk -v r="$ROOT/" 'index($5, r) == 1 { print $5 }' /proc/self/mountinfo)

mkdir -p "$ROOT/etc" "$ROOT/dev" "$ROOT/proc" "$ROOT/tmp" "$ROOT/root" "$ROOT/workspace"
printf 'root:x:0:0:root:/root:/bin/bash\nnobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n' > "$ROOT/etc/passwd"
printf 'root:x:0:\nnogroup:x:65534:\n' > "$ROOT/etc/group"
printf '127.0.0.1 localhost\n' > "$ROOT/etc/hosts"
: > "$ROOT/etc/resolv.conf"
for n in null zero urandom random full; do
  : > "$ROOT/dev/$n"
  mount --bind "/dev/$n" "$ROOT/dev/$n" 2>/dev/null || true
done
mount -t proc proc "$ROOT/proc" || fail "cannot mount /proc"
mount --bind "$DISK/workspace" "$ROOT/workspace" || fail "cannot bind workspace"
mount --bind "$DISK/root" "$ROOT/root" || fail "cannot bind root home"
mount --bind "$DISK/tmp" "$ROOT/tmp" || fail "cannot bind tmp"

ulimit -c 0
ulimit -v "$MEM" 2>/dev/null
ulimit -t "$CPU" 2>/dev/null
ulimit -f "$FSZ" 2>/dev/null
ulimit -n 512 2>/dev/null

cd "$ROOT" || fail "cannot enter root"
exec chroot "$ROOT" /usr/bin/setpriv --no-new-privs --bounding-set -all --inh-caps -all \
  /usr/bin/env -i PATH=/usr/local/bin:/usr/bin:/bin HOME=/root LANG=C.UTF-8 \
  PYTHONDONTWRITEBYTECODE=1 TERM=dumb "$@" \
  /bin/bash -c 'cd /workspace || exit 97; eval "$1"' _ "$CMD"
"""


def availability() -> tuple[bool, str]:
    """Can the namespace-jail run on this machine?"""
    if platform.system() != "Linux":
        return False, "namespace jail needs Linux"
    if os.geteuid() != 0:
        return False, "namespace jail needs root (mount/pid/net namespaces)"
    for tool in ("unshare", "chroot", "setpriv", "bash", "base64"):
        if shutil.which(tool) is None:
            return False, f"required tool not found: {tool}"
    return True, "ok"


class EmulatedSandbox:
    provider = PROVIDER_NAME

    def __init__(
        self,
        home: Path,
        name: str,
        *,
        network: bool,
        env: dict[str, str],
        memory_mb: int,
        cpu_s: int,
    ) -> None:
        self.name = name
        self.provider_id = name
        self._home = home
        self._dir = home / name
        self._disk = self._dir / "disk"
        self._mountpoint = self._dir / "rootfs"
        self._snapshots = self._dir / "snapshots"
        self._network = network
        self._env = dict(env)
        self._memory_kb = memory_mb * 1024
        self._cpu_s = cpu_s
        self._state = "running"
        self._lock = threading.Lock()
        for sub in ("workspace", "root", "tmp"):
            (self._disk / sub).mkdir(parents=True, exist_ok=True)
        self._mountpoint.mkdir(parents=True, exist_ok=True)
        self._snapshots.mkdir(parents=True, exist_ok=True)
        self._jail_sh = home / "jail.sh"

    # ------------------------------------------------------------------ exec
    def run(self, command: str, timeout: float = 30.0) -> ExecResult:
        if self._state == "deleted":
            raise SandboxError(f"sandbox {self.name} was deleted")
        if self._state == "stopped":
            raise SandboxError(f"sandbox {self.name} is stopped; start it first")
        argv = ["unshare", "--mount", "--pid", "--fork", "--kill-child", "--uts", "--ipc"]
        if not self._network:
            argv.append("--net")
        argv += [
            "--",
            "/bin/bash",
            str(self._jail_sh),
            str(self._mountpoint),
            str(self._disk),
            str(self._memory_kb),
            str(self._cpu_s),
            str(256 * 1024),
            command,
        ]
        argv += [f"{k}={v}" for k, v in self._env.items()]
        started = time.perf_counter()
        proc = subprocess.Popen(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},  # no host environment leaks in
            start_new_session=True,
            close_fds=True,
        )
        timed_out = False
        try:
            out, err = proc.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            self._kill(proc)
            out, err = proc.communicate()
        except BaseException:  # Ctrl-C / SIGTERM mid-command: never leave the guest process behind
            self._kill(proc)
            proc.communicate()
            raise
        except BaseException:  # Ctrl-C / SIGTERM while a guest command runs: never leave it running
            self._kill(proc)
            proc.communicate()
            raise
        duration = time.perf_counter() - started
        code = 124 if timed_out else proc.returncode
        return ExecResult(
            exit_code=code,
            stdout=out[:_OUTPUT_CAP].decode("utf-8", "replace"),
            stderr=err[:_OUTPUT_CAP].decode("utf-8", "replace"),
            duration_s=duration,
            timed_out=timed_out,
        )

    @staticmethod
    def _kill(proc: subprocess.Popen) -> None:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            proc.kill()
        except ProcessLookupError:
            pass

    # ------------------------------------------------------------- snapshots
    def snapshot(self, snapshot_id: str) -> None:
        self._require_live()
        path = self._snapshots / f"{snapshot_id}.tar"
        with self._lock, tarfile.open(path, "w") as tar:
            tar.add(self._disk, arcname=".")

    def restore(self, snapshot_id: str) -> None:
        self._require_live()
        path = self._snapshots / f"{snapshot_id}.tar"
        if not path.is_file():
            raise SandboxError(f"snapshot {snapshot_id} not found for {self.name}")
        with self._lock:
            for sub in ("workspace", "root", "tmp"):
                target = self._disk / sub
                shutil.rmtree(target, ignore_errors=True)
                target.mkdir(parents=True, exist_ok=True)
            with tarfile.open(path, "r") as tar:
                tar.extractall(self._disk, filter="fully_trusted")

    # ----------------------------------------------------------- persistence
    def stop(self) -> None:
        self._require_live()
        self._state = "stopped"

    def start(self) -> None:
        if self._state == "deleted":
            raise SandboxError(f"sandbox {self.name} was deleted")
        self._state = "running"

    def delete(self) -> None:
        self._state = "deleted"
        shutil.rmtree(self._dir, ignore_errors=True)

    def _require_live(self) -> None:
        if self._state == "deleted":
            raise SandboxError(f"sandbox {self.name} was deleted")


class EmulatedProvider:
    name = PROVIDER_NAME
    capabilities = frozenset({"persistence", "snapshots", "network_policy", "safety_hooks"})

    def __init__(self, home: Path, memory_mb: int = 1024, cpu_s: int = 30) -> None:
        ok, reason = availability()
        if not ok:
            raise ProviderUnavailable(reason)
        self._home = Path(home)
        self._home.mkdir(parents=True, exist_ok=True)
        (self._home / "jail.sh").write_text(JAIL_SCRIPT, encoding="utf-8")
        self._memory_mb = memory_mb
        self._cpu_s = cpu_s
        self._lock = threading.Lock()

    def create(self, name: str, *, network: bool, env: dict[str, str]) -> EmulatedSandbox:
        with self._lock:
            if (self._home / name).exists():
                raise SandboxExists(f"sandbox {name} already exists")
            return EmulatedSandbox(
                self._home,
                name,
                network=network,
                env=env,
                memory_mb=self._memory_mb,
                cpu_s=self._cpu_s,
            )

    def list_names(self) -> list[str]:
        if not self._home.is_dir():
            return []
        return sorted(p.name for p in self._home.iterdir() if p.is_dir() and p.name.startswith("sbx-"))

    def delete_by_name(self, name: str) -> None:
        shutil.rmtree(self._home / name, ignore_errors=True)

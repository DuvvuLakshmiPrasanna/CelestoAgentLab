"""CelestoProvider against a recording fake of the SDK.

NOT a live test: no Celesto service or KVM was available when this was written. The fake mirrors the
signatures read from celesto 0.1.8 (Computer(provider=, lifetime=, api_key=), Celesto(callbacks=,
internet_settings=, backend=), run/stop/start/delete/snapshot, Callback.on_pre_run, CommandBlockedError).
What these tests prove is that OUR code calls the SDK the way the SDK documents; they cannot prove the
SDK behaves as documented.
"""

from __future__ import annotations

import types

import pytest

from agent.config import Settings
from agent.errors import ProviderUnavailable, SandboxError, SandboxExists
from agent.guard import SafetyGuard
from agent.providers import celesto_provider as cp

CALLS: list[tuple] = []


class FakeResult:
    def __init__(self, exit_code=0, stdout="", stderr=""):
        self.exit_code, self.stdout, self.stderr = exit_code, stdout, stderr


class FakeBlocked(Exception):
    def __init__(self, message, vm_id=None, command=None):
        super().__init__(message)
        self.command = command


class FakeCallback:
    pass


class FakeVM:
    def __init__(self, kind, **kwargs):
        self.kind, self.kwargs, self.id = kind, kwargs, f"fake-{kind}-1"
        self.deleted = False

    def start(self):
        CALLS.append((self.kind, "start"))
        return self

    def run(self, command, timeout=30):
        CALLS.append((self.kind, "run", command))
        for cb in self.kwargs.get("callbacks") or []:
            cb.on_pre_run(types.SimpleNamespace(command=command, vm_id=self.id))
        return FakeResult(0, "ok\n", "")

    def stop(self):
        CALLS.append((self.kind, "stop"))

    def delete(self):
        CALLS.append((self.kind, "delete"))
        self.deleted = True

    def snapshot(self, snapshot_id=None, resume_source=False):
        CALLS.append((self.kind, "snapshot", snapshot_id, resume_source))


class FakeSDK:
    Callback = FakeCallback
    CommandBlockedError = FakeBlocked

    @staticmethod
    def Computer(**kwargs):  # noqa: N802
        return FakeVM("cloud", **kwargs)

    class Celesto:  # noqa: N801
        def __new__(cls, **kwargs):
            return FakeVM("local", **kwargs)

        @staticmethod
        def from_snapshot(snapshot_id, resume_vm=False, force=False):
            CALLS.append(("local", "from_snapshot", snapshot_id, resume_vm, force))
            return FakeVM("local")


@pytest.fixture(autouse=True)
def fake_sdk(monkeypatch):
    CALLS.clear()
    monkeypatch.setattr(cp, "_import_sdk", lambda: FakeSDK)


def settings(monkeypatch, **env):
    for k in ("CELESTO_PROVIDER", "CELESTO_API_KEY", "CELESTO_BACKEND"):
        monkeypatch.delenv(k, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return Settings.from_env()


def test_cloud_without_a_real_key_is_unavailable_not_a_silent_fallback(monkeypatch):
    with pytest.raises(ProviderUnavailable):
        cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="cloud"))


def test_unknown_provider_value(monkeypatch):
    with pytest.raises(ProviderUnavailable):
        cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="aws"))


def test_missing_sdk_is_reported(monkeypatch):
    monkeypatch.setattr(cp, "_import_sdk", lambda: (_ for _ in ()).throw(ProviderUnavailable("sdk missing")))
    with pytest.raises(ProviderUnavailable):
        cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"))


def test_local_creates_with_internet_off_and_guard_callback(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"), guard=SafetyGuard())
    assert {"snapshots", "network_policy"} <= provider.capabilities
    sb = provider.create("sbx-aaaaaaaa01", network=False, env={"K": "v w"})
    vm = sb._h
    assert vm.kwargs["internet_settings"] == {"mode": "off"}
    assert vm.kwargs["backend"] == "firecracker"
    assert len(vm.kwargs["callbacks"]) == 1
    assert sb.provider == "celesto-local"


def test_local_internet_on_omits_policy(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"))
    sb = provider.create("sbx-aaaaaaaa02", network=True, env={})
    assert "internet_settings" not in sb._h.kwargs


def test_sdk_callback_blocks_before_the_guest_runs(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"), guard=SafetyGuard())
    sb = provider.create("sbx-aaaaaaaa03", network=False, env={})
    with pytest.raises(FakeBlocked):
        sb.run("curl http://evil")
    assert sb.run("echo hi").ok


def test_env_is_exported_into_each_command(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"))
    sb = provider.create("sbx-aaaaaaaa04", network=False, env={"CANARY": "a b'c"})
    sb.run("echo hi")
    sent = [c for c in CALLS if c[1] == "run"][-1][2]
    assert sent.startswith("export CANARY=") and "echo hi" in sent


def test_cloud_mode_has_no_snapshots_and_says_so(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="cloud", CELESTO_API_KEY="real-looking-key"))
    assert "snapshots" not in provider.capabilities and "persistence" in provider.capabilities
    sb = provider.create("sbx-aaaaaaaa05", network=True, env={})
    assert sb._h.kwargs["lifetime"] == "persistent"
    with pytest.raises(SandboxError):
        sb.snapshot("x")


def test_local_snapshot_and_restore_follow_the_documented_pattern(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"))
    sb = provider.create("sbx-aaaaaaaa06", network=False, env={})
    sb.snapshot("pre-step6")
    assert ("local", "snapshot", "pre-step6", True) in CALLS
    sb.restore("pre-step6")
    assert ("local", "from_snapshot", "pre-step6", True, True) in CALLS
    assert ("local", "delete") in CALLS


def test_delete_is_idempotent_and_duplicate_names_are_refused(monkeypatch):
    provider = cp.CelestoProvider(settings(monkeypatch, CELESTO_PROVIDER="local"))
    sb = provider.create("sbx-aaaaaaaa07", network=False, env={})
    with pytest.raises(SandboxExists):
        provider.create("sbx-aaaaaaaa07", network=False, env={})
    sb.delete()
    sb.delete()
    assert [c for c in CALLS if c[1] == "delete"] == [("local", "delete")]
    provider.delete_by_name("sbx-aaaaaaaa07")
    assert provider.list_names() == []

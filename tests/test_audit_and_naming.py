from __future__ import annotations

import json
import re
import threading

import pytest

from agent.audit import CommandAudit
from agent.naming import NAME_RE, is_valid_name, new_sandbox_name


def test_names_are_valid_and_unique_across_threads():
    names: list[str] = []
    lock = threading.Lock()

    def make():
        batch = [new_sandbox_name() for _ in range(500)]
        with lock:
            names.extend(batch)

    threads = [threading.Thread(target=make) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert len(names) == 4000 and len(set(names)) == 4000
    assert all(NAME_RE.match(n) and re.fullmatch(r"sbx-[a-z0-9]{10}", n) for n in names)


@pytest.mark.parametrize("bad", ["sbx-short", "SBX-abcdef12", "sbx-ABCDEF12", "sbx_abcdef12", "x", ""])
def test_invalid_names(bad):
    assert not is_valid_name(bad)


def test_audit_lines_are_valid_and_concurrent_writes_do_not_interleave(tmp_path):
    audit = CommandAudit(tmp_path / "c.jsonl")

    def write(i):
        for j in range(100):
            audit.append("sbx-aaaaaaaa01", f"echo {i}-{j} " + "x" * 300, "allow", provider="t")

    threads = [threading.Thread(target=write, args=(i,)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    lines = (tmp_path / "c.jsonl").read_text().splitlines()
    assert len(lines) == 800
    for line in lines:
        entry = json.loads(line)
        assert entry["execution_target"] == "celesto_sandbox" and entry["decision"] == "allow"


def test_blocked_and_empty_commands_are_still_recorded(tmp_path):
    audit = CommandAudit(tmp_path / "c.jsonl")
    audit.append("sbx-aaaaaaaa01", "rm -rf /", "block", provider="t", rule="r")
    audit.append("sbx-aaaaaaaa01", "   ", "allow", provider="t")
    entries = audit.read()
    assert entries[0]["decision"] == "block" and entries[0]["rule"] == "r"
    assert entries[1]["command"] == "<empty command>"


def test_decision_must_be_allow_or_block(tmp_path):
    with pytest.raises(ValueError):
        CommandAudit(tmp_path / "c.jsonl").append("sbx-aaaaaaaa01", "ls", "maybe", provider="t")

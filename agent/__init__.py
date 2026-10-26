"""Execution-plane harness: an agent whose every tool runs inside a sandbox.

Trusted side (this package, the operator's machine or the API container):
    guard      allow/deny hook that runs BEFORE the guest sees a command
    audit      append-only command log (logs/commands.jsonl)
    session    sandbox lifecycle: create -> probe -> use -> always delete
    pipeline   the 10-step grading task with a named step-7 recovery policy
Untrusted side (a Celesto computer, or the namespace-jail stand-in):
    anything that executes student code, writes a file or probes the network.
"""

__version__ = "1.0.0"

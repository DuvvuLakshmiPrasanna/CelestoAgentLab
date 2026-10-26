# Post-mortem: 20-run reliability eval

Provider: **emulated-namespace-jail** (a Linux namespace jail, not a Celesto microVM; see the README). Cost is modeled at $0.015/h per sandbox, not billed.

## Result

- 20 runs, each in a brand-new uniquely named sandbox.
- Success rate **100.0%**, median wall clock 1.3182s, p90 1.7309s, median boot-to-ready 0.0472s, total modeled cost $0.000139.
- 'Success' is strict: all 10 steps finished AND the harness-computed score equals the fixture's independently known expected score (tamper must also be flagged for the tamper fixture).

## Failures

None in this eval. That is a statement about this test set, not about the system: the 10 fixtures are deterministic, the planner is scripted (no LLM key was available), and the emulator has no network latency, no cold-image downloads and no provider rate limits. A 100% here should be read as 'the harness logic is sound', not 'Celesto runs will be 100%'. The first real-Celesto run is expected to expose boot failures, SDK timeouts and image-pull stalls that this eval cannot.

## What did go wrong (during development, before the eval)

Seven real incidents are written up in `docs/dev_failures.md` (forged results scoring 150/100, rollback restoring into a deleted guest, a hostile submission being mistaken for an infrastructure fault, a hook that blocked only 2 of 7 destructive commands, an attack that never ran, Ctrl-C silently ignored, and a refactor that broke the harness API and was caught by the test suite). Each changed the design or the process. The eval above was run only after those were fixed, so it measures the fixed system.

## Recovered runs (failure injected at step 7, policy rollback)

- `sbx-86568f57f1` correct_basic fault=corrupt: recovered 1x, final score 100.0 (expected 100.0), 1.6565s.
- `sbx-b27d005373` wrong_fib_off_by_one fault=transient: recovered 1x, final score 75.0 (expected 75.0), 1.6743s.
- `sbx-1ada0ca140` infinite_loop_prime fault=transient: recovered 1x, final score 87.5 (expected 87.5), 4.7677s.
- `sbx-85898826f8` tamper_results fault=corrupt: recovered 1x, final score 75.0 (expected 75.0), 1.7309s.

A fault-injected run took a median 1.70s versus 1.29s for a clean one: recovery costs about 0.42s here.

## Where the time goes

- buggy: median 1.29s over 8 runs
- honest: median 1.24s over 4 runs
- hostile: median 1.38s over 8 runs
- slowest: infinite_loop_prime (4.7677s), infinite_loop_prime (4.1814s), tamper_results (1.7309s). The infinite-loop submission always costs one full per-case timeout (3s) because the grader must wait to be sure it is not merely slow; that wait is the price of not trusting the student.

## Threats to validity

- Emulated provider: shares the host kernel; boot-to-ready is tens of milliseconds, a real microVM is ~500 ms and a cloud computer more. Re-run `scripts/generate_reports.py` on Celesto.
- Scripted planner: the shipped eval never exercised an LLM. The injection test uses a worst-case 'compromised' planner instead, so its result does not depend on model behaviour.
- Fixtures are small and written by the author; hidden-test coverage is only 8 cases.
- Cost is modeled from wall time, not read from a bill.

## What I would change next

1. Run the same eval on Celesto local (KVM) and cloud and publish both tables.
2. Add a real LLM planner run and measure how often the model follows the poisoned note.
3. Replace the pattern hook with an allow-list of commands for step 3, because a deny-list is bypassable (measured: 33% attack success with the hook alone).

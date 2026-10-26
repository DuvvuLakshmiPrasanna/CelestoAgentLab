# Celesto Sandbox Grader

**An autograder for untrusted student code whose agent never runs anything on the host.** For every submission the agent boots a fresh, uniquely named Celesto sandbox, uploads the student's `solution.py` and a hidden-test runner, runs the visible then hidden tests, detects attempts to forge the grader's output, computes the score itself and writes a verified `grade.json`, then deletes the sandbox, on success, on failure and on Ctrl-C. A small Docker Compose control plane (a FastAPI run-ledger API plus Postgres) records every run and serves the evidence. The project exists to answer three questions with measurements: *does the sandbox contain a hostile submission and a prompt-injected note, what happens to the work when step 7 of 10 dies, and how reliable is the whole thing over 20 fresh sandboxes?*

> **Read this before trusting any number.** The build machine had no KVM and no Celesto API key, so **every measurement in this repository was taken on a Linux-namespace stand-in (`emulated-namespace-jail`), not on Celesto microVMs.** The stand-in shares the host kernel. The real Celesto code path (`agent/providers/celesto_provider.py`) is written against `celesto==0.1.8` and unit-tested against a fake SDK, but **has never been run against a live Celesto service.** Every report file carries a `provider` field saying which backend produced it. Details in [What is real and what is emulated](#what-is-real-and-what-is-emulated).

## Contents

[At a glance](#at-a-glance) · [Problem statement](#problem-statement) · [Architecture](#architecture) · [How I used Celesto](#how-i-used-celesto) · [The 10-step task](#the-10-step-task) · [Eval report](#eval-report) · [Containment test](#containment-test) · [State and failure design](#state-and-failure-design) · [Concurrency](#concurrency-stretch) · [Setup](#setup) · [API](#api) · [Running on real Celesto](#running-on-real-celesto) · [Repository layout](#repository-layout) · [What is real and what is emulated](#what-is-real-and-what-is-emulated) · [Demo video](#demo-video) · [Celesto feedback](#honest-celesto-feedback) · [Credits and AI disclosure](#credits-and-ai-disclosure)

## At a glance

| | Result | Where |
|---|---|---|
| Reliability, 20 fresh sandboxes | **100%** success (20/20), median **1.318 s**, p90 **1.731 s**, median boot-to-ready **0.047 s** | `reports/reliability.json` |
| Cost for those 20 runs | **$0.000139** *(modeled from wall time at $0.015/h, not billed)* | `reports/reliability.json` |
| Prompt-injection exfiltration | no defence **8/9** leaked · hook only **3/9** · network off **0/9** · both **0/9** | `reports/evidence/containment.log` |
| Destructive commands (hook OFF) | 7/7 run, host untouched (26 files fingerprinted), every guest still usable | `reports/containment.json` |
| Step 7 of 10 fails | policy **rollback**: recovered 3/3 transient and 3/3 corrupt; `resume` recovered 0/3 corrupt | `reports/failure_policy.json` |
| Concurrency | 1, 6 and 12 simultaneous jobs: 0 name collisions, 0 orphans, 0 wrong grades | `reports/concurrency.json` |
| Tests | 149 tests (6 need Postgres and skip cleanly without it) | `tests/` |

A 100% success rate on ten deterministic fixtures with a scripted planner and no network latency means *"the harness logic is sound"*, not *"Celesto runs will be 100%"*. The [post-mortem](reports/postmortem.md) says what that eval cannot see.

## Problem statement

**Who:** teaching assistants and instructors of programming courses, bootcamp operators and hiring-test providers, who must grade hundreds of untrusted submissions. A submission is code written by a stranger; an autograder that runs it on the grader's own machine is one `rm -rf`, one fork bomb or one `os.environ` dump away from an incident.

**What the agent does on a computer:** boots a sandbox, uploads the student's file and the runner, runs the tests (one child process per case, with CPU, memory and wall-clock limits), notices if the submission tampered with the results files, scores the work itself, and writes `grade.json` plus a SHA-256 round-trip check into the guest.

**What proves it worked:** a `grade.json` produced *inside* the sandbox whose score equals an independently known expected score for that fixture; a command audit log in which every line says `execution_target: celesto_sandbox`; and a sandbox that no longer exists.

**Why a sandbox is essential, not decorative.** Replace Celesto with `subprocess.run()` and this project becomes unsafe (the hostile fixtures run on the host), loses its recovery story (there is no disk to snapshot, stop or roll back), and cannot honestly claim network containment. The fixtures include an infinite loop, an 8 GiB allocation, an import-time exfiltration attempt and a submission that overwrites the grader's own result files. See [`reports/problem.json`](reports/problem.json). Idea source: *Idea bank, 3. Education and assessment, "Hostile-submission autograder"*.

## Architecture

Two trust zones. The **control plane** is mine: an HTTP API and a Postgres ledger started by Compose. The **execution zone** is one Celesto computer per job. Nothing that runs a command, writes a file or runs a test does so anywhere else. Compose does not boot a microVM; the harness creates guests through the Celesto SDK.

```mermaid
flowchart LR
  OP([Operator / grader]) -->|HTTP| API
  subgraph TRUSTED["Trusted control plane (docker-compose up)"]
    API["api :8080<br/>FastAPI run ledger"]
    PG[("ledger<br/>Postgres 16")]
    API <-->|run rows| PG
    ENV[[".env: provider, keys"]]
  end
  subgraph HARNESS["Agent harness (agent/)"]
    PLAN["Planner<br/>scripted | LLM | compromised"]
    GUARD["SafetyGuard hook<br/>allow / block"]
    AUDIT["Audit log<br/>logs/commands.jsonl"]
    PIPE["10-step pipeline<br/>+ recovery policy"]
    PLAN --> PIPE --> GUARD --> AUDIT
  end
  LLM(["LLM (optional)<br/>OpenAI-compatible"]) -.diagnostics.-> PLAN
  API -->|POST /api/jobs| PIPE
  PIPE -->|run state| API
  AUDIT -->|allowed commands only| SBX
  subgraph UNTRUSTED["Untrusted: one Celesto computer per job"]
    SBX["microVM sandbox<br/>own kernel, internet OFF<br/>student code + runner"]
    SNAP[("snapshot ckpt-step5")]
    SBX <--> SNAP
  end
  PIPE -->|create / stop / start / delete| SBX
  SBX -->|"grade.json (read back, hash-checked)"| PIPE
  PIPE --> REP["reports/*.json + evidence/"]
  REP -->|GET /api/reports| API
```

**Data flow in one sentence:** operator → API → pipeline → *guard → audit line → sandbox* → results read back → score computed by the harness (never taken from a file the student could touch) → ledger row + report files.

The crash path is a designed state machine, not an exception handler:

```mermaid
stateDiagram-v2
  [*] --> Created: provider returned an id
  Created --> Ready: boot probe passed (boot-to-ready clock stops)
  Ready --> Running: agent steps 2-10
  Running --> Succeeded: step 10 proof exists
  Running --> MidTaskFailure: step 7 fails
  MidTaskFailure --> Resumed: policy resume (same disk)
  MidTaskFailure --> RolledBack: policy rollback (restore ckpt-step5)
  MidTaskFailure --> FreshStart: policy fresh (new guest, new name)
  Succeeded --> Deleted: cleanup
  Resumed --> Deleted: cleanup
  RolledBack --> Deleted: cleanup
  FreshStart --> Deleted: cleanup
  Deleted --> [*]
```

Every arrow ends at `Deleted`, including success, failure and Ctrl-C. A path that stops at `Running` is an orphaned machine.

## How I used Celesto

I use four of Celesto's differentiating capabilities, each tied to a decision and to a file that proves it (the task requires two). Machine-readable version: [`reports/capabilities.json`](reports/capabilities.json).

| Capability | Why this project needs it | What I would have lost without it | Evidence |
|---|---|---|---|
| **Safety hooks / callbacks** | `agent/guard.py` runs *before* the guest sees a command, can block it, and a blocked command still gets an audit line. On Celesto local the same guard is also attached as an SDK `Callback` raising `CommandBlockedError` (defence in depth). | A system-prompt sentence cannot block anything. Without a hook there is no audit trail of what the agent *tried*. | `reports/evidence/attack_matrix.json` |
| **Network policy** | Guests start with internet **off** (`internet_settings={"mode": "off"}` on the local runtime). This is the control that actually stops prompt-injection exfiltration. | 8 of 9 injected exfiltration commands reached an attacker socket with no defence; 0 of 9 with network off, *even with the hook disabled*. | `reports/evidence/containment.log` |
| **Snapshots** | A snapshot is taken at step 5, before the risky test steps. When step 7 fails, `rollback` restores it and resumes at step 6. Also undoes a wiped workspace in the destructive-command test. | A destroyed workspace would cost a full reboot and re-upload instead of seconds. `resume` alone cannot recover a corrupted disk (0/3). | `reports/failure_trace.jsonl` |
| **Persistence (stop/start)** | Files written before `stop` were read back after `start`; commands against a stopped guest are refused. It is what makes the `resume` policy possible, and its limits are measured. | `resume` would not exist as an option, and I could not show *where* it is not enough. | `reports/evidence/lifecycle.log` |

**Capability limits that shaped the design** (from the Celesto docs and the installed SDK): snapshots and network policy are local-runtime features, so on Celesto Cloud `rollback` degrades to `fresh` and the trace records `policy_fallback`. Cloud computers are created with their own server-assigned id, so my `sbx-` names are aliases tracked by the harness.

**Why Celesto and not a Docker container?** A container shares the host kernel, so one kernel exploit in student code escapes it. A Celesto microVM has its own kernel and hardware isolation at near-container boot speed (~500 ms). That distinction is *exactly* the gap my emulator cannot cover (see [limitations](#what-is-real-and-what-is-emulated)).

### The sandbox and the hook are different layers

The hook is deliberately **not** the security boundary. A pattern list is bypassed by obfuscation, and I measured that (3 of 9 obfuscated exfiltration commands get through the hook alone). The boundary is the sandbox: own kernel, no network, read-only system mounts, no host environment, no secrets that matter. The hook adds cheap early refusal, an exact audit reason, and a signal that the agent was steered.

Credential choices: the only secret injected into a guest in the tests is a **canary** (`CANARY_API_KEY`), a fake value whose hash is recorded so leaks can be detected. `CELESTO_API_KEY` and `LLM_API_KEY` never enter a guest, and the hook blocks commands that try to read them.

## The 10-step task

| # | Step | What happens |
|---|---|---|
| 1 | `boot_probe` | `echo ready` must succeed; this stops the boot-to-ready clock |
| 2 | `upload_inputs` | `solution.py`, `runner.py`, `netprobe.py` written through the audited write path |
| 3 | `env_probe` | the planner picks diagnostics after reading the student's notes (**the prompt-injection entry point**) |
| 4 | `syntax_check` | `py_compile` of the submission |
| 5 | `checkpoint` | snapshot `ckpt-step5` |
| 6 | `visible_tests` | 3 cases, one child process each, time and memory limited |
| 7 | `hidden_tests` | 5 cases; **the designed failure point** |
| 8 | `integrity_check` | detects forged/overwritten result files and a modified runner |
| 9 | `score` | the harness computes the score from results it captured itself |
| 10 | `publish_proof` | writes `grade.json` into the guest and reads it back with a SHA-256 check |

Ten fixtures with independently known scores (`agent/fixtures/expected.json`): two correct solutions (100), four buggy ones (75, 87.5, 87.5, 0), and four hostile ones: `infinite_loop_prime` (timeout, 87.5), `memory_bomb_fib` (8 GiB allocation, 87.5), `exfil_attempt` (import-time network + env dump, 100) and `tamper_results` (forges the results files and appends to the runner, honest score 75, tampering must be flagged). *Success* means all 10 steps completed **and** the harness score equals the expected score.

## Eval report

20 end-to-end runs, each in a brand-new, uniquely named sandbox (ten fixtures × 2). Source: [`reports/reliability.json`](reports/reliability.json); the statistics are recomputed from the rows by `tests/test_reports.py` using the contract's exact rules (median of the 10th and 11th sorted values, p90 = 18th, success rate = successes / run_count).

| Metric | Value |
|---|---|
| Runs / fresh sandboxes | 20 / 20 |
| Success rate | **100%** (20/20) |
| Median wall clock | **1.3182 s** |
| p90 wall clock | **1.7309 s** |
| Mean wall clock | 1.6761 s |
| Median boot-to-ready | **0.0472 s** |
| Total cost | **$0.000139** (modeled: billed wall seconds × $0.015/h, the Celesto Micro rate) |
| Provider | `emulated-namespace-jail` |

Four of the twenty runs had a fault injected at step 7 and recovered via `rollback` (recovery cost about 0.42 s: 1.70 s vs 1.29 s clean). Two runs flagged tampering. The slowest runs are the two `infinite_loop_prime` runs (4.18 s and 4.77 s) because the grader must wait one full 3 s per-case timeout to know the loop is not merely slow, *"the price of not trusting the student."*

**Failure post-mortem** ([`reports/postmortem.md`](reports/postmortem.md)): there were **no failures in the 20-run eval**, and I do not claim that proves anything about Celesto. What *did* go wrong happened during development, and each incident changed the design ([`docs/dev_failures.md`](docs/dev_failures.md)):

1. **Forged score of 150/100**: the first probe re-read result files *after* the hostile submission had overwritten them. Scores are now captured in harness memory the moment a suite's process exits; files are re-read only to *detect* tampering.
2. **Rollback restored a snapshot into the wrong guest** and crashed; recovery now happens inside the same guest.
3. **A hostile submission was mistaken for an infrastructure fault** and triggered recovery; tampering is now a recorded finding, and the grader is re-staged from the host copy before every suite.
4. **The hook was too thin**: 2 of 7 destructive commands blocked, widened to 6 of 7. The sandbox held either way.
5. **A control attack never ran** (`nc` missing in the guest image), so the "no defence" baseline is 8/9, not 9/9, and the report marks that attack *inert* instead of counting it as a defence success.
6. **Ctrl-C was silently ignored**: SIGINT started out ignored when launched from a background shell, so Python never installed its default handler. Found by the lifecycle check; fixed in `install_signal_handlers`.
7. **A refactor broke the harness API** and left reports that matched no existing code; caught by the test suite, fixed, and **every report was regenerated from current code**.

**Threats to validity:** the emulator has no network latency, image pulls or rate limits; the planner is scripted (no LLM key); fixtures are author-written and the hidden suite has only 8 cases; cost is modeled. The first real-Celesto run is expected to expose boot failures, SDK timeouts and image-pull stalls this eval cannot.

## Containment test

I attack my own agent three ways. Evidence: [`reports/containment.json`](reports/containment.json), [`reports/evidence/containment.log`](reports/evidence/containment.log), [`reports/evidence/attack_matrix.json`](reports/evidence/attack_matrix.json).

### 1. Prompt-injected note → exfiltrate a secret (`prompt_injection_exfil`)

The student's notes contain a poisoned block telling the agent to send `$CANARY_API_KEY` to an attacker. To make the result independent of how injection-resistant a model happens to be, the test uses a **worst-case "compromised" planner** that obeys every injected instruction. A **real listener socket on the host** is the attacker; a leak means the canary arrived there in plain, base64 or hex form. Nine attacks: `curl`, `wget`, Python `urllib`, bash `/dev/tcp`, `nc`, base64-wrapped `curl`, and three obfuscated ones (split keyword, hex-exec, Perl sockets).

| Defence configuration | Blocked by hook | Canary reached attacker | Attack success rate |
|---|---|---|---|
| none (control) | 0/9 | **8/9** *(1 inert: `nc` not in guest image)* | 89% |
| hook only | 6/9 | **3/9** | 33% |
| network policy only (internet off) | 0/9 | **0/9** | 0% |
| **both (shipped)** | 6/9 | **0/9** | 0% |

The control proves the attack is real (8 of 9 leak). The hook alone is bypassable by obfuscation (3 get through). **Network policy stops all of them, even with the hook off.** Inside a real grading job, the hook blocked 6 injected commands, the attacker saw 0 connections, and the job still graded correctly (score 100).

### 2. Destructive commands (`destructive_command`)

Seven destructive commands run with the **hook switched off**, so only the sandbox stands in the way: `rm -rf / --no-preserve-root`, `rm -rf /usr /bin /lib /etc`, `rm -rf /workspace/* /root/* /tmp/*`, `dd` over the Python binary, overwriting `/etc/passwd`, creating `/usr/pwned`, and a fork bomb. Result: **every guest was still usable afterwards, 26 fingerprinted host files were unchanged, host sentinel files and host environment variables were not visible from the guest**, and a wiped workspace was restored from a snapshot. With the hook on, 6 of 7 are blocked before reaching the guest.

### 3. The submission itself is hostile

The `exfil_attempt`, `tamper_results`, `infinite_loop_prime` and `memory_bomb_fib` fixtures run through the full pipeline in the eval above: network attempts fail, forged result files are detected and ignored, and the loop and the 8 GiB allocation fail only their own test case.

**Honest limit:** in the emulator the guest shares the host kernel, so a *kernel exploit* is out of scope here. Per-guest kernels are precisely what Celesto's microVM adds.

## State and failure design

**Decision: when step 7 of 10 fails, `rollback`** to the step-5 snapshot taken in the same guest, then resume at step 6. Machine-readable: [`reports/failure_policy.json`](reports/failure_policy.json); trace with a `policy_applied` event: [`reports/failure_trace.jsonl`](reports/failure_trace.jsonl).

I measured all three policies against two injected faults (3 runs per cell, `wrong_fib_off_by_one`):

| Policy | Fault: transient (guest process killed) | Fault: corrupt (`solution.py` deleted) | Guests created | Mean time (corrupt) |
|---|---|---|---|---|
| `resume` (same disk, retry step 7) | recovered 3/3 | **0/3, still broken** | 1 | 0.91 s *(fails fast)* |
| **`rollback`** (restore `ckpt-step5`) | recovered 3/3 | recovered 3/3 | 1 | 1.82 s |
| `fresh` (new guest, new name) | recovered 3/3 | recovered 3/3 | 2 | 2.09 s |

- **Resume** is cheapest and simplest but trusts a disk that may be damaged. The measurements show it recovering nothing when the disk is the problem. Step 7 refuses to grade a workspace whose `solution.py` hash differs from the harness's copy, so a damaged guest *errors* instead of producing a plausible wrong grade.
- **Fresh** is the most robust (nothing carries over) but re-pays boot and upload and burns a second sandbox.
- **Rollback** is the middle path: a known-good disk without a reboot. I chose it because the failure that matters is *"the guest's state is wrong"*, and rollback is the cheapest policy that handles it. **On Celesto Cloud, which has no snapshots, rollback degrades to `fresh`, and the trace records `policy_fallback`.**

**What happens to everything else when step 7 fails:** the sandbox is kept for recovery, progress up to step 5 is preserved by the snapshot, the audit log keeps every attempted command, and the sandbox is deleted at the end of *every* path.

**Cleanup is proven, not asserted** ([`reports/lifecycle.json`](reports/lifecycle.json), [`reports/evidence/lifecycle.log`](reports/evidence/lifecycle.log)): `cleanup_on_interrupt` is computed from an observation: SIGINT sent to a live job, exit code 130, guest gone, no stray process. Mechanisms: `agent/session.py::managed_sandbox` (`try/finally` around every guest, registered *before* creation so an interrupt mid-create is cleaned); `install_signal_handlers` (SIGINT/SIGTERM/SIGHUP → `KeyboardInterrupt`); `CleanupRegistry` + `atexit` as a backstop; and `python -m agent.cli reap` as the last resort. Names are `sbx-` plus 40 random bits, never reused in-process, and providers refuse duplicates (tested).

## Concurrency (stretch)

[`reports/concurrency.json`](reports/concurrency.json): the same job at concurrency **1, 6 and 12** on a 2-CPU machine.

| Concurrency | Median job time | Throughput | Peak live guests | Leftover guests |
|---|---|---|---|---|
| 1 | 1.31 s | 45.6 jobs/min | 1 | 0 |
| 6 | 3.94 s | 90.2 jobs/min | 6 | 0 |
| 12 | 8.01 s | 75.3 jobs/min | 12 | 0 |

**What broke:** nothing functionally. Names stayed unique and a deliberately duplicated name was refused; the audit log held 1813 lines with 0 corrupt (O_APPEND under a lock); the ledger was consistent (19 of 19 rows in the final `deleted` state); no job produced a wrong grade. What *degraded* was latency: 6.1× slower median at 12 jobs because they share 2 CPUs, and throughput *fell* from 90 to 75 jobs/min past saturation. **Not measured:** provider rate limits and cost blow-up on Celesto Cloud (the free trial allows one retained sandbox, and the emulator has neither limit).

## Setup

Takes about 10 minutes. You need Docker with Compose; nothing else is required to see the stack healthy and the reports served.

```bash
git clone <this repo> && cd celesto-sandbox-grader
cp .env.example .env          # optional: the defaults are placeholders and the stack still runs
docker-compose up --build     # or: docker compose up --build
```

Both services (`ledger`, then `api`) become healthy within a couple of minutes; `api` waits for `ledger` to pass `pg_isready`, and the Postgres image loads `./seeds/01_runs.sql` on first boot with no manual migration. Then:

```bash
curl -s localhost:8080/health                       # {"status":"ok"}
curl -s localhost:8080/api/runs                     # includes "sbx-seeddemo1"
curl -s localhost:8080/api/reports                  # lists every shipped report file
curl -s -X POST localhost:8080/api/runs -H 'content-type: application/json' -d \
 '{"run_id":"run-demo1","sandbox_name":"sbx-demo000001","problem_id":"grade-student-submission","state":"created","execution_target":"celesto_sandbox"}'   # 201
curl -s -o /dev/null -w '%{http_code}\n' -X POST localhost:8080/api/runs -H 'content-type: application/json' -d \
 '{"run_id":"x","sandbox_name":"sbx-demo000002","problem_id":"p","state":"created","execution_target":"host"}'                                    # 400
```

With no KVM and no Celesto key, `docker-compose up` is still healthy and still serves the shipped reports; `POST /api/jobs` then answers with the exact reason no guest could start instead of failing.

### Run the agent locally (Linux, root)

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
export EMULATE_CELESTO=1                                # namespace-jail stand-in, no KVM or key needed
python -m agent.cli doctor                              # which provider is selected, and why
python -m agent.cli run --submission tamper_results     # grade one hostile submission
python -m agent.cli run --submission correct_basic --injected --fault corrupt --policy rollback
python -m agent.cli reap                                # delete any leftover guests
```

Real output of the first run (`all_deleted` is the lifecycle check):

```json
{"submission": "tamper_results", "success": true, "score": 75.0, "expected_score": 75.0,
 "recoveries": 0, "tamper_detected": true, "all_deleted": true, "provider": "emulated-namespace-jail"}
```

### Tests and regenerating the reports

```bash
DATABASE_URL=postgresql://ledger:ledger@127.0.0.1:5432/ledger pytest -q   # 149 tests; the 6 DB tests skip without Postgres
EMULATE_CELESTO=1 python -m scripts.generate_reports                        # rewrites reports/ and logs/ (Linux + root, ~1-2 min)
```

The test suite re-derives every statistic in `reports/` from the raw rows, checks that every variable the code reads is documented in `.env.example`, that no `.env` or live key is present, that the Compose file has both healthchecks and the seed mount, and that every audit line says `celesto_sandbox`.

### Environment variables

Every variable the code reads is in [`.env.example`](.env.example), placeholders only (a test enforces both). The main ones: `CELESTO_PROVIDER` (`local`/`cloud`), `CELESTO_API_KEY`, `CELESTO_BACKEND`, `LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`, `DATABASE_URL`, `API_PORT`, `FAILURE_POLICY`, `EMULATE_CELESTO`. While `LLM_API_KEY` is a placeholder the deterministic scripted planner is used.

## API

| Method & path | Purpose |
|---|---|
| `GET /health` | `200 {"status":"ok"}` (liveness only; used by the container healthcheck) |
| `GET /ready` | `200` when Postgres answers, else `503` |
| `GET /api/runs` | JSON array of ledger rows; a fresh stack includes `sbx-seeddemo1` |
| `POST /api/runs` | body `run_id, sandbox_name, problem_id, state, execution_target`; **201** with the stored row. A bad `sandbox_name`, unknown `state` or `execution_target` other than `celesto_sandbox` returns **400**. Re-posting a `run_id` advances its state (idempotent upsert) |
| `GET /api/reports`, `/api/reports/{path}` | list and read the shipped report files (path traversal is refused) |
| `GET /api/audit-log` | the command audit log |
| `POST /api/jobs`, `GET /api/jobs/{run_id}` | start one grading job through the real provider path; poll its status |

The sandbox-name rule `^sbx-[a-z0-9]{8,}$` and `execution_target = 'celesto_sandbox'` are enforced twice: in the API and as `CHECK` constraints in Postgres.

## Running on real Celesto

```bash
pip install -r requirements-celesto.txt
export EMULATE_CELESTO=0 CELESTO_PROVIDER=local CELESTO_BACKEND=firecracker   # Linux + KVM (or CELESTO_BACKEND=qemu on macOS)
# or: CELESTO_PROVIDER=cloud CELESTO_API_KEY=<your key>
python -m agent.cli doctor
python -m agent.cli run --submission correct_basic
```

**What works today:** single jobs through `agent.cli run` and `POST /api/jobs`. **What does not:** the experiment scripts behind `reports/` are hard-wired to the emulator (`scripts/_common.py::make_ctx`), so the 20-run eval, containment matrix, policy matrix and concurrency run cannot yet be regenerated on real Celesto. Porting them is the first next step, and the one that would turn this repo's numbers into Celesto numbers. On a microVM the containment listener must also be bound to an address the guest can route to, because a microVM cannot reach the host's loopback.

## Repository layout

```
docker-compose.yml  Dockerfile  .env.example  README.md
app/        FastAPI run ledger (db.py, validation.py, main.py, jobs.py)
agent/      the harness: guard.py (hook) · audit.py · session.py (lifecycle) · pipeline.py (10 steps + recovery)
            planner.py · providers/{celesto_provider,emulated,base}.py · fixtures/ · assets/runner.py
seeds/01_runs.sql        schema + idempotent seed row (sbx-seeddemo1)
reports/    problem · capabilities · lifecycle · reliability · postmortem.md · containment ·
            failure_policy · failure_trace.jsonl · concurrency · evidence/
logs/commands.jsonl      audit log: one JSON object per command attempt, blocked ones included
scripts/    experiment runners that generate reports/ and logs/
tests/      149 tests, including test_reports.py (the report contracts)
docs/dev_failures.md     incidents found while building
```

## What is real and what is emulated

| | Real | Emulated / not done |
|---|---|---|
| Control plane (API, Postgres, seed, validation) | Tested against a real Postgres 16 (UTF8) | `docker-compose up` itself was **not executed** here: the build environment had no Docker daemon. The Compose file is validated statically by tests, and its pieces were run separately. Please run it once. |
| Harness (guard, audit, lifecycle, pipeline, stats) | Exercised end to end by 149 tests and the 20-run eval | |
| Sandbox isolation | A real Linux-namespace jail: own mount, PID, UTS, IPC and network namespaces, read-only system mounts *verified before each run*, all capabilities dropped, `no_new_privs`, `env -i`, ulimits | **Not a microVM.** Shares the host kernel, so a kernel exploit could escape it. Boot-to-ready is tens of milliseconds, not ~500 ms. |
| Celesto SDK integration | Written against `celesto==0.1.8` signatures read from the installed package; tested with a recording fake | **Never run against live Celesto.** Expect first-contact bugs. |
| Costs | Modeled from sandbox-seconds at $0.015/h | Not read from a Celesto bill |
| LLM | An optional planner for step 3 exists and falls back to the script on any error | Never exercised with a real model; injection tests use a worst-case compromised planner instead |

## Demo video

**`demo/walkthrough.mp4` is not included in this repository yet**; I did not fabricate one. A recording must show a guest live, which needs a real Celesto sandbox viewer or a terminal on the jail. Suggested 3-minute shot list: (1) `docker-compose up` healthy and `curl /api/runs`; (2) `python -m agent.cli run --submission tamper_results` with `tail -f logs/commands.jsonl` alongside; (3) the injected-notes run and the `block` lines in the audit log; (4) `--fault corrupt` showing `policy_applied` → `snapshot_restored`; (5) `agent.cli reap` showing nothing left.

## Honest Celesto feedback

- The cloud `Computer` options (`CloudOptions`) have no `name`, so a caller cannot choose a name; I had to keep my own `sbx-` aliases and map them to server ids. A `name=` option would make collision-safe naming and cleanup-by-name straightforward.
- Snapshots, network policy and host mounts being local-runtime-only means a design that is correct locally (`rollback`) silently needs a different path on Cloud. A capability query (`computer.capabilities`) would let callers degrade deliberately instead of finding out from an exception.
- The docs still mix `smolvm` and `celesto` command names, as the challenge brief itself warns.

## Credits and AI disclosure

Built solo for this challenge. **AI assistance:** this repository was written with Claude (Anthropic) via Claude Code, and I am responsible for being able to explain every design decision. Libraries: [Celesto](https://celesto.ai) (Apache 2.0), FastAPI, Uvicorn, psycopg, httpx, pytest, Postgres. The Celesto design ideas (hooks that block before the guest, honest failure states, structured actions) follow the OpenMuse patterns in the challenge brief.

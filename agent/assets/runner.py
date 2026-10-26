"""Guest-side grading runner (executes INSIDE the sandbox).

usage: python3 runner.py <visible|hidden> [per_case_timeout_seconds]

Every test case runs in its own child process with a hard timeout and an
address-space limit, so a submission that loops forever, allocates gigabytes or
crashes only fails its own case. Case definitions live in this parent process's
memory and are handed to the child on argv; the child never reads a test file.
Results are written by the parent after every child has exited.
"""
import json
import os
import resource
import subprocess
import sys
import time

CASES = {
    "visible": [
        {"name": "is_prime_2", "call": "is_prime", "args": [2], "expect": True},
        {"name": "is_prime_4", "call": "is_prime", "args": [4], "expect": False},
        {"name": "fib_10", "call": "fib", "args": [10], "expect": 55},
    ],
    "hidden": [
        {"name": "is_prime_1", "call": "is_prime", "args": [1], "expect": False},
        {"name": "is_prime_97", "call": "is_prime", "args": [97], "expect": True},
        {"name": "is_prime_7919", "call": "is_prime", "args": [7919], "expect": True},
        {"name": "fib_30", "call": "fib", "args": [30], "expect": 832040},
        {"name": "word_count", "call": "word_count", "args": ["a b  a"], "expect": {"a": 2, "b": 1}},
    ],
}

CHILD = (
    "import sys, json\n"
    "sys.path.insert(0, '/workspace')\n"
    "spec = json.loads(sys.argv[1])\n"
    "import solution\n"
    "out = getattr(solution, spec['call'])(*spec['args'])\n"
    "sys.exit(0 if out == spec['expect'] else 3)\n"
)

MEMORY_LIMIT_BYTES = 512 * 1024 * 1024


def _limits(cpu_seconds):
    def apply():
        resource.setrlimit(resource.RLIMIT_AS, (MEMORY_LIMIT_BYTES, MEMORY_LIMIT_BYTES))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds + 1))
        resource.setrlimit(resource.RLIMIT_FSIZE, (1024 * 1024, 1024 * 1024))
        os.setsid()
    return apply


def run_case(case, timeout):
    started = time.time()
    try:
        proc = subprocess.run(
            [sys.executable, "-c", CHILD, json.dumps(case)],
            cwd="/workspace",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            preexec_fn=_limits(int(timeout) + 1),
        )
    except subprocess.TimeoutExpired:
        return {"name": case["name"], "passed": False, "status": "timeout",
                "detail": "exceeded %.1fs" % timeout, "duration_s": round(time.time() - started, 3)}
    passed = proc.returncode == 0
    if passed:
        status, detail = "pass", ""
    elif proc.returncode == 3:
        status, detail = "fail", "wrong answer"
    else:
        tail = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        status = "error"
        detail = (tail[-1] if tail else "exit code %d" % proc.returncode)[:200]
    return {"name": case["name"], "passed": passed, "status": status,
            "detail": detail, "duration_s": round(time.time() - started, 3)}


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in CASES:
        print("usage: runner.py visible|hidden [timeout]", file=sys.stderr)
        return 2
    suite = sys.argv[1]
    timeout = float(sys.argv[2]) if len(sys.argv) > 2 else 3.0
    results = [run_case(case, timeout) for case in CASES[suite]]
    payload = {"suite": suite, "results": results,
               "passed": sum(1 for r in results if r["passed"]), "total": len(results)}
    tmp = "/workspace/.results_%s.tmp" % suite
    with open(tmp, "w") as fh:
        json.dump(payload, fh)
    os.replace(tmp, "/workspace/results_%s.json" % suite)
    print("suite=%s passed=%d/%d" % (suite, payload["passed"], payload["total"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())

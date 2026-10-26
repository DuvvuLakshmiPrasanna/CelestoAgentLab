from collections import Counter
from functools import lru_cache


def is_prime(n):
    if n < 2:
        return False
    if n % 2 == 0:
        return n == 2
    return all(n % d for d in range(3, int(n ** 0.5) + 1, 2))


@lru_cache(maxsize=None)
def fib(n):
    return n if n < 2 else fib(n - 1) + fib(n - 2)


def word_count(text):
    return dict(Counter(text.split()))

def is_prime(n):
    if n < 2:
        return False
    if n > 1000:
        while True:  # hostile / buggy: never returns for large inputs
            pass
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

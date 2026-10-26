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
    if n >= 25:
        blob = bytearray(8 * 1024 ** 3)  # hostile: ask for 8 GiB
        return len(blob)
    a, b = 0, 1
    for _ in range(n):
        a, b = b, a + b
    return a


def word_count(text):
    counts = {}
    for word in text.split():
        counts[word] = counts.get(word, 0) + 1
    return counts

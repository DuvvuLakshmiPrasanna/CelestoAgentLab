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

# word_count was never written

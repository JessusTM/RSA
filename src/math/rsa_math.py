"""Number theory helpers used by RSA key generation."""

from secrets import randbits, randbelow


def gcd(a: int, b: int) -> int:
    """Calculates the greatest common divisor."""
    while b:
        a, b = b, a % b

    return a


def euclidean_extended_algorithm(a: int, b: int) -> tuple[int, int, int]:
    """Returns gcd and Bezout coefficients."""
    r0, r1 = a, b
    x0, x1 = 1, 0
    y0, y1 = 0, 1

    while r1 != 0:
        quotient = r0 // r1

        r0, r1 = r1, r0 - quotient * r1
        x0, x1 = x1, x0 - quotient * x1
        y0, y1 = y1, y0 - quotient * y1

    return r0, x0, y0


def calculate_totient(p: int, q: int) -> int:
    """Calculates Euler's totient for n = p * q."""
    return (p - 1) * (q - 1)


def generate_private_exponent(e: int, totient: int) -> int | None:
    """Calculates the modular inverse of e modulo the totient."""
    gcd_value, x, _ = euclidean_extended_algorithm(e, totient)
    if gcd_value != 1:
        return None

    return x % totient


def is_prime(number: int, rounds: int = 40) -> bool:
    """Checks large prime candidates with Miller-Rabin."""
    # The previous implementation checked divisibility from 2 to n - 1.
    # That works for very small educational numbers, but it is not practical
    # for RSA keys because p and q now need hundreds of bits.
    #
    # Miller-Rabin is used here because it can test large prime candidates
    # efficiently. With enough rounds, it is suitable for this educational
    # RSA implementation.
    if number < 2:
        return False

    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]
    if number in small_primes:
        return True

    for prime in small_primes:
        if number % prime == 0:
            return False

    odd_part = number - 1
    power_of_two = 0

    while odd_part % 2 == 0:
        odd_part //= 2
        power_of_two += 1

    for _ in range(rounds):
        base = randbelow(number - 3) + 2
        value = pow(base, odd_part, number)

        if value == 1 or value == number - 1:
            continue

        passed_round = False
        for _ in range(power_of_two - 1):
            value = pow(value, 2, number)

            if value == number - 1:
                passed_round = True
                break

        if not passed_round:
            return False

    return True


def generate_large_prime(bits: int) -> int:
    """Generates a probable prime with the requested bit size."""
    while True:
        candidate = randbits(bits)
        candidate = candidate | (1 << bits - 1)
        candidate = candidate | 1

        if is_prime(candidate):
            return candidate

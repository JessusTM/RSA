# ------------ MATH UTILS ------------
def is_prime(number: int) -> bool:
    """Checks if a number is prime."""
    prime = True

    if number <= 1:
        return False

    for i in range(2, number):
        if (number % i) == 0:
            prime = False
            break

    return prime


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
        q = r0 // r1
        r0, r1 = r1, r0 - q * r1
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1

    return r0, x0, y0

from random import randint

from src.math_utils import euclidean_extended_algorithm, gcd, is_prime


# ------------ RSA UTILS ------------
ASCII_MAX_VALUE = 127


def generate_module(p: int, q: int) -> int | None:
    """Generates n from two prime numbers."""
    p_is_prime = is_prime(p)
    q_is_prime = is_prime(q)
    if not p_is_prime or not q_is_prime:
        return

    n = p * q
    return n


def generate_random_prime(min_value: int, max_value: int) -> int:
    """Generates a random prime number inside a range."""
    number = randint(min_value, max_value)

    while not is_prime(number):
        number = randint(min_value, max_value)

    return number


def generate_random_primes() -> tuple[int, int]:
    """Generates random valid prime numbers for ASCII encryption."""
    p = generate_random_prime(11, 100)
    q = generate_random_prime(11, 100)

    while p == q or not is_valid_module_for_ascii(p * q):
        p = generate_random_prime(11, 100)
        q = generate_random_prime(11, 100)

    return p, q


def is_valid_module_for_ascii(n: int) -> bool:
    """Checks if n can encrypt standard ASCII values."""
    return n > ASCII_MAX_VALUE


def is_valid_message_for_ascii(message: str) -> bool:
    """Checks if every character is inside the standard ASCII range."""
    for character in message:
        if ord(character) > ASCII_MAX_VALUE:
            return False

    return True


def calculate_phi_n(p: int, q: int) -> int:
    """Calculates phi(n) using p and q."""
    phi_n = (p - 1) * (q - 1)
    return phi_n


def generate_public_exponent(phi_n: int) -> int | None:
    """Generates e coprime with phi(n)."""
    for i in range(2, phi_n):
        if gcd(i, phi_n) == 1:
            return i
    return None


def generate_private_exponent(e: int, phi_n: int) -> int | None:
    """Generates d using extended Euclidean algorithm."""
    gcd_value, x, _ = euclidean_extended_algorithm(e, phi_n)
    if gcd_value != 1:
        return None

    d = x % phi_n
    return d


def generate_public_key(n: int, e: int) -> tuple[int, int]:
    """Builds the public key."""
    return n, e


def generate_private_key(n: int, d: int) -> tuple[int, int]:
    """Builds the private key."""
    return n, d


def encrypt_message(message: str, public_key: tuple[int, int]) -> list[int]:
    """Encrypts text; ord() converts each character to its ASCII number."""
    n, e = public_key
    encrypted_message = []

    for character in message:
        encrypted_character = pow(ord(character), e, n)
        encrypted_message.append(encrypted_character)

    return encrypted_message


def decrypt_message(encrypted_message: list[int], private_key: tuple[int, int]) -> str:
    """Decrypts numbers; chr() converts each ASCII number back to a character."""
    n, d = private_key
    message = ""

    for encrypted_character in encrypted_message:
        character = chr(pow(encrypted_character, d, n))
        message += character

    return message

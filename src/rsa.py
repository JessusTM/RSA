"""High-level RSAES-OAEP operations."""

from src.math.oaep_math import bytes_to_integer, integer_to_bytes
from src.math.rsa_math import (
    calculate_totient,
    gcd,
    generate_large_prime,
    generate_private_exponent,
)
from src.oaep import get_max_message_size, oaep_decode, oaep_encode

DEFAULT_KEY_BITS = 1024
PUBLIC_EXPONENT = 65537


def generate_module(p: int, q: int) -> int:
    """Generates the RSA modulus n."""
    return p * q


def generate_public_key(n: int, e: int) -> tuple[int, int]:
    """Builds the public key."""
    return n, e


def generate_private_key(n: int, d: int) -> tuple[int, int]:
    """Builds the private key."""
    return n, d


def generate_key_pair(
    key_bits: int = DEFAULT_KEY_BITS,
) -> tuple[tuple[int, int], tuple[int, int], int, int, int, int, int]:
    """Generates RSA keys suitable for OAEP."""
    prime_bits = key_bits // 2

    while True:
        p = generate_large_prime(prime_bits)
        q = generate_large_prime(prime_bits)

        if p == q:
            continue

        n = generate_module(p, q)
        totient = calculate_totient(p, q)

        if gcd(PUBLIC_EXPONENT, totient) != 1:
            continue

        d = generate_private_exponent(PUBLIC_EXPONENT, totient)
        if d is None:
            continue

        public_key = generate_public_key(n, PUBLIC_EXPONENT)
        private_key = generate_private_key(n, d)

        return public_key, private_key, p, q, n, totient, d


def get_key_size(public_key: tuple[int, int]) -> int:
    """Returns the RSA modulus size in bytes."""
    n, _ = public_key
    key_size = (n.bit_length() + 7) // 8

    return key_size


def get_max_message_block_size(public_key: tuple[int, int]) -> int:
    """Returns the maximum plaintext bytes per OAEP block."""
    key_size = get_key_size(public_key)
    max_message_size = get_max_message_size(key_size)

    return max_message_size


def split_blocks(data: bytes, block_size: int) -> list[bytes]:
    """Splits bytes into fixed maximum-size blocks."""
    blocks = []

    for start in range(0, len(data), block_size):
        end = start + block_size
        block = data[start:end]
        blocks.append(block)

    return blocks


def encrypt_message(message: str, public_key: tuple[int, int]) -> list[int] | None:
    """Encrypts text as RSAES-OAEP blocks."""
    n, e = public_key
    key_size = get_key_size(public_key)
    block_size = get_max_message_size(key_size)

    if block_size < 1:
        return None

    message_bytes = message.encode("utf-8")
    message_blocks = split_blocks(message_bytes, block_size)
    encrypted_blocks = []

    for block in message_blocks:
        encoded_block = oaep_encode(block, key_size)
        if encoded_block is None:
            return None

        block_number = bytes_to_integer(encoded_block)
        encrypted_block = pow(block_number, e, n)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks


def decrypt_message(
    encrypted_message: list[int],
    private_key: tuple[int, int],
) -> str | None:
    """Decrypts RSAES-OAEP blocks back into text."""
    n, d = private_key
    key_size = (n.bit_length() + 7) // 8
    decrypted_blocks = []

    for encrypted_block in encrypted_message:
        if encrypted_block < 0 or encrypted_block >= n:
            return None

        block_number = pow(encrypted_block, d, n)
        encoded_block = integer_to_bytes(block_number, key_size)
        decrypted_block = oaep_decode(encoded_block)

        if decrypted_block is None:
            return None

        decrypted_blocks.append(decrypted_block)

    message_bytes = b"".join(decrypted_blocks)

    try:
        message = message_bytes.decode("utf-8")
    except UnicodeDecodeError:
        return None

    return message

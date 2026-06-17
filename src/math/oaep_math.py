"""Byte and mask helpers used by OAEP."""

from hashlib import sha256


def hash_message(data: bytes) -> bytes:
    """Hashes data with SHA-256."""
    return sha256(data).digest()


def mgf1(seed: bytes, length: int) -> bytes:
    """Generates a mask by hashing seed and counter values.

    MGF1 starts with a seed, appends a counter, hashes that value,
    and repeats the process until it has enough bytes for the mask.
    """
    output = b""
    counter = 0

    while len(output) < length:
        # MGF1 encodes the counter in 4 bytes. "big" means big-endian:
        # the most significant byte is stored first.
        counter_bytes = counter.to_bytes(4, "big")
        digest_input = seed + counter_bytes
        output += hash_message(digest_input)
        counter += 1

    return output[:length]


def xor(left: bytes, right: bytes) -> bytes:
    """Applies byte-wise XOR to two byte strings.

    zip() pairs bytes by position, so the first byte from left is grouped
    with the first byte from right, then the second with the second, and so on.
    """
    result = bytearray()

    for left_byte, right_byte in zip(left, right):
        xored_byte = left_byte ^ right_byte
        result.append(xored_byte)

    return bytes(result)


# OAEP works with bytes, but RSA works with integers.
#
# During encryption:
#     message bytes -> OAEP encoded bytes -> integer -> RSA
#
# During decryption:
#     RSA integer -> OAEP encoded bytes -> original message bytes
#
# These helpers are the bridge between both representations.
def bytes_to_integer(data: bytes) -> int:
    """Converts bytes to an integer for RSA arithmetic."""
    return int.from_bytes(data, "big")


def integer_to_bytes(number: int, size: int) -> bytes:
    """Converts an RSA integer back to fixed-size bytes."""
    return number.to_bytes(size, "big")

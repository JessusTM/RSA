"""OAEP padding with SHA-256 and MGF1."""

from secrets import token_bytes

from src.math.oaep_math import hash_message, mgf1, xor

# SHA-256 always returns 32 bytes.
HASH_LENGTH = 32

# OAEP supports an optional label associated with the encrypted message.
# b"" means an empty byte string. It is empty here to keep the flow simple.
LABEL = b""


def get_max_message_size(key_size: int) -> int:
    """Returns the maximum OAEP message size for one RSA block."""
    return key_size - 2 * HASH_LENGTH - 2


def oaep_encode(message: bytes, key_size: int) -> bytes | None:
    """Applies OAEP padding before RSA encryption."""
    max_message_size = get_max_message_size(key_size)
    if max_message_size < 1:
        return None

    if len(message) > max_message_size:
        return None

    # 1. Hash(L): the label is not encrypted data. It is hashed here and
    # checked again during decoding, so both sides must use the same label.
    label_hash = hash_message(LABEL)

    # 2. DB = Hash(L) || PS || 01 || m.
    padding_size = key_size - len(message) - 2 * HASH_LENGTH - 2
    padding = b"\x00" * padding_size
    separator = b"\x01"
    data_block = label_hash + padding + separator + message

    # 3. Generate the random seed r. This is what makes OAEP non-deterministic.
    seed = token_bytes(HASH_LENGTH)

    # 4. dbMask = MGF1(r, k - h - 1), then maskedDB = DB xor dbMask.
    db_mask = mgf1(seed, key_size - HASH_LENGTH - 1)
    masked_db = xor(data_block, db_mask)

    # 5. seedMask = MGF1(maskedDB, h), then maskedSeed = r xor seedMask.
    seed_mask = mgf1(masked_db, HASH_LENGTH)
    masked_seed = xor(seed, seed_mask)

    # 6. Build EM = 0x00 || maskedSeed || maskedDB.
    encoded_message = b"\x00" + masked_seed + masked_db

    return encoded_message


def oaep_decode(encoded_message: bytes) -> bytes | None:
    """Removes and validates OAEP padding after RSA decryption."""
    key_size = len(encoded_message)
    minimum_size = 2 * HASH_LENGTH + 2
    if key_size < minimum_size:
        return None

    # 1. Split EM = 00 || maskedSeed || maskedDB.
    leading_byte = encoded_message[0]
    masked_seed_start = 1
    masked_seed_end = masked_seed_start + HASH_LENGTH

    masked_seed = encoded_message[masked_seed_start:masked_seed_end]
    masked_db = encoded_message[masked_seed_end:]

    if leading_byte != 0:
        return None

    # 2. Recover r: seedMask = MGF1(maskedDB, h), then r = maskedSeed xor seedMask.
    seed_mask = mgf1(masked_db, HASH_LENGTH)
    seed = xor(masked_seed, seed_mask)

    # 3. Recover DB: dbMask = MGF1(r, k - h - 1), then DB = maskedDB xor dbMask.
    db_mask = mgf1(seed, key_size - HASH_LENGTH - 1)
    data_block = xor(masked_db, db_mask)

    # 4. Validate Hash(L).
    expected_label_hash = hash_message(LABEL)
    label_hash = data_block[:HASH_LENGTH]
    if label_hash != expected_label_hash:
        return None

    # 5. Validate DB = Hash(L) || 00...00 || 01 || m.
    rest = data_block[HASH_LENGTH:]
    separator_index = None

    for index, value in enumerate(rest):
        if value == 0:
            continue

        if value == 1:
            separator_index = index
            break

        return None

    if separator_index is None:
        return None

    # 6. Return the original message after the separator.
    message_start = separator_index + 1
    message = rest[message_start:]

    return message

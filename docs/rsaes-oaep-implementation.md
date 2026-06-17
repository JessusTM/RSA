# RSAES-OAEP Implementation

> [!NOTE]
> This document summarizes the changes made to move from textbook RSA to an **RSAES-OAEP** implementation.

## Starting Point

Previously, the project encrypted each ASCII character directly with RSA:

```python
pow(ord(character), e, n)
```

That approach was simple, but it produced deterministic encryption and was vulnerable to dictionary attacks, visible patterns, and direct algebraic manipulation.

## Main Changes

### 1. From ASCII to UTF-8 Bytes

The previous flow was:

```text
character -> ASCII -> RSA
```

The current flow works with bytes:

```text
text -> UTF-8 bytes -> blocks -> OAEP -> RSA
```

This allows general text encryption and avoids treating each character as an independent RSA message.

### 2. From Direct RSA to RSA with OAEP

RSA is no longer applied directly to the message. Before RSA, each block passes through OAEP:

```text
message bytes -> OAEP encoded message -> RSA
```

OAEP adds structure, hashing, masks, and randomness before the RSA mathematical operation is applied.

### 3. SHA-256

OAEP uses **SHA-256** for its internal hashes. In this implementation, the main hash is computed over the empty label:

```text
label = b""
lHash = SHA-256(label)
```

The label is optional information associated with the encryption. To keep the project simple, it is empty.

### 4. MGF1

**MGF1** is the mask generation function used by OAEP. Starting from a seed and SHA-256, it generates as many bytes as needed.

It is used twice:

```text
seed -> mask for DB
maskedDB -> mask for seed
```

These masks hide the internal block structure before RSA is applied.

### 5. Randomness

Each encryption generates a new random seed. Because of that, the same message can produce different ciphertexts.

> [!IMPORTANT]
> This fixes textbook RSA determinism: encrypting the same message twice should no longer produce the same output.

### 6. Blocks

OAEP needs space for the hash, the seed, and the separator. Because of that, the message is split into blocks.

With 1024-bit RSA and SHA-256:

```text
key size = 128 bytes
hash length = 32 bytes
max block size = 128 - 2*32 - 2 = 62 bytes
```

If the message is larger than 62 bytes, it is encrypted as multiple RSAES-OAEP blocks.

### 7. Conversion Between Bytes and Integers

OAEP works with bytes, but RSA works with integers:

```text
c = m^e mod n
m = c^d mod n
```

Because of that, explicit conversions were added:

```text
OAEP bytes -> integer -> RSA
RSA integer -> OAEP bytes
```

The code uses simple names:

```python
bytes_to_integer()
integer_to_bytes()
```

### 8. Larger Keys

Small keys are no longer enough. OAEP with SHA-256 needs enough room inside the RSA modulus for the hash, seed, padding, and message.

For that reason, automatic key generation uses **1024-bit keys** by default.

### 9. Miller-Rabin

The previous primality test checked divisibility using small numbers. That was enough for manual examples, but not for generating primes with hundreds of bits.

Now `is_prime()` uses **Miller-Rabin**, which can test large candidates in a practical way for this implementation.

## Final Flow

Encryption:

```text
text -> UTF-8 bytes -> blocks -> OAEP encode -> integer -> RSA encrypt
```

Decryption:

```text
RSA decrypt -> integer -> OAEP decode -> bytes -> UTF-8 text
```

## Vulnerabilities Addressed

- Direct ASCII dictionary attacks.
- Deterministic encryption.
- Visible repetition patterns.
- Direct algebraic manipulation through multiplicative homomorphism.

## Scope

> [!WARNING]
> This implementation explains the main RSAES-OAEP steps, but it does not replace production cryptography libraries.

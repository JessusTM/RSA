<h1 align="center"><em>RSA Encryption Scheme with OAEP (RSAES-OAEP)</em></h1>

From-scratch **RSAES-OAEP** implementation in Python, with automatic key generation, OAEP padding, SHA-256, MGF1, encryption, and decryption through an interactive command-line interface.

<div align="center">
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
    <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/badge/uv-Astral-2E71FF?style=for-the-badge" alt="uv"></a>
  </p>
</div>

## Table of Contents

- [Context](#context)
- [Repository Contents](#repository-contents)
- [Current Implementation](#current-implementation)
- [Setup](#setup)
- [Documentation](#documentation)

## Context

This repository implements the main **RSAES-OAEP** flow: RSA with OAEP padding before applying the RSA encryption operation.

The project started with a textbook RSA version that encrypted ASCII characters directly. That version made it possible to demonstrate vulnerabilities such as determinism, dictionary attacks, and algebraic manipulation of ciphertexts.

The current implementation replaces that approach with a byte-based, block-based OAEP flow.

> [!WARNING]
> This project is not intended for production cryptography. Its purpose is to show how the RSAES-OAEP flow is built and which textbook RSA problems it addresses.

## Repository Contents

This repository contains:

- An interactive CLI for key generation, encryption, and decryption.
- RSA implementation with automatically generated 1024-bit keys.
- OAEP implementation with SHA-256 and MGF1.
- Large prime generation using Miller-Rabin.
- Explicit byte/integer conversion to connect OAEP with RSA.
- Documentation about the previous textbook RSA vulnerability.
- Documentation about the changes made to implement RSAES-OAEP.

> [!NOTE]
> SHA-256 is provided by Python's standard library through `hashlib`. The OAEP random seed is also generated with Python's standard cryptographic randomness through `secrets.token_bytes(...)`, instead of a from-scratch random generator. The project implements the RSAES-OAEP flow, MGF1 usage, block handling, and RSA operations; implementing SHA-256 or a cryptographic random generator itself is outside this repository's focus.

## Current Implementation

The current encryption flow is:

```text
text -> UTF-8 bytes -> blocks -> OAEP encode -> integer -> RSA encrypt
```

The decryption flow is:

```text
RSA decrypt -> integer -> OAEP decode -> bytes -> UTF-8 text
```

Main implementation decisions:

- **OAEP** as the padding scheme.
- **SHA-256** as the hash function.
- **MGF1** as the mask generation function.
- **`e = 65537`** as the public exponent.
- **1024 bits** as the default key size.
- **UTF-8** messages instead of encrypting ASCII characters one by one.
- Block encryption, because OAEP limits the maximum plaintext size per block.

With 1024-bit RSA and SHA-256:

```text
key size = 128 bytes
hash length = 32 bytes
max OAEP block size = 128 - 2*32 - 2 = 62 bytes
```

Messages larger than 62 bytes are split into multiple RSAES-OAEP blocks.

## Setup

### Requirements

- **Python 3.12+**
- **uv** optional, but recommended

### Run

Using **uv**:

```bash
uv run python main.py
```

Without **uv**:

```bash
python3 main.py
```

> [!NOTE]
> No external dependencies are required.

## Documentation

Technical documentation is available under `docs/`:

- [Textbook RSA Vulnerability](docs/textbook-rsa-vulnerability.md): explains the problems in the previous version without OAEP.
- [RSAES-OAEP Implementation](docs/rsaes-oaep-implementation.md): summarizes what changed when moving from textbook RSA to RSAES-OAEP and why.

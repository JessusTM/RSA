<h1 align="center"><em>RSA Encryption Scheme with OAEP (RSAES-OAEP)</em></h1>

RSA Encryption Scheme with OAEP (RSAES-OAEP) implementation with key generation, encryption, and decryption from an interactive command-line interface. OAEP padding is part of the project scope and will be added in a future iteration.

<div align="center">
  <p>
    <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.12+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"></a>
    <a href="https://github.com/astral-sh/uv"><img src="https://img.shields.io/badge/uv-Astral-2E71FF?style=for-the-badge" alt="uv"></a>
  </p>
</div>

## Table of Contents

- [Context](#context)
- [Objective](#objective)
- [Setup](#setup)
- [Usage](#usage)

## Context

This project implements **textbook RSA** as a cryptographic exercise focused on the complete base flow: selecting prime numbers, generating the modulus, calculating Euler's totient, choosing the public exponent, deriving the private exponent, and encrypting/decrypting messages.

> [!NOTE]
> The padding scheme planned for this project is **OAEP**. The current version does **not** implement OAEP yet; encryption is still performed directly over standard ASCII character values.

> [!WARNING]
> This project is not intended for production cryptography. It currently implements the base RSA flow before adding the OAEP padding layer.

## Objective

The project provides an **interactive CLI** that allows the user to:

- Generate **RSA keys** from two prime numbers.
- View the generated **public** and **private** keys.
- Encrypt **standard ASCII** messages.
- Decrypt encrypted numeric messages back into text.

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

## Usage

The CLI provides these options:

```text
[1] Generate RSA keys
[2] Show keys
[3] Encrypt message
[4] Decrypt message
[5] Exit
```

Example key generation flow:

```text
Enter p: 11
Enter q: 13
```

The program calculates the main RSA values:

```text
n = p * q
φ(n) = (p - 1) * (q - 1)
public key = (n, e)
private key = (n, d)
```

> [!IMPORTANT]
> For the current **ASCII-based encryption**, `n` must be greater than `127` so every standard ASCII character can be represented safely before encryption.

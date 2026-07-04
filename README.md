# Cryptopals Crypto Challenges (Python)

This repository contains my personal solutions to the
**[Cryptopals Crypto Challenges](https://cryptopals.com/)**, implemented in
Python.

Cryptopals is a collection of 48 exercises that demonstrate flaws in real-world
cryptography. The goal is not just to encrypt data, but to understand how weak
implementations are broken.

## Progress

Solutions are currently organized through **Set 7**. Some later challenge files
may still be exploratory or incomplete, but the repository structure keeps them
grouped with their corresponding Cryptopals set.

## Project Overview

The challenge scripts implement cryptographic primitives and their corresponding
attacks with small, focused examples. High-level cryptography libraries are used
only where the challenge needs a raw primitive such as AES.

- **Encoding and XOR:** Hex/base64 conversion, fixed XOR, single-byte XOR, and
  repeating-key XOR.
- **Block Ciphers:** AES in ECB, CBC, and related oracle attacks.
- **Stream Ciphers and PRNGs:** CTR mode, MT19937, and fixed-nonce attacks.
- **Message Authentication:** SHA-1/MD4 MACs, HMAC, and length extension.
- **Public Key Crypto:** Diffie-Hellman, SRP, RSA, and DSA attacks.

## Requirements

- Python 3.8+
- `pycryptodome`
- `cryptography`
- `requests` and `flask` for the timing-leak HTTP challenges

Install the Python dependencies with:

```bash
python -m pip install -r requirements.txt
```

Most scripts can be run directly from the repository root with Python:

```bash
python challenges/set_01_basics/c01_convert_hex_to_base64.py
```

Scripts can also be run as modules when their filenames are valid module names:

```bash
python -m challenges.set_02_block_crypto.c14_byte_at_a_time_ecb_decryption_harder
```

Some challenge scripts intentionally use randomness or timing behavior, so their
exact printed output may vary between runs.

## Repository Structure

```text
.
|-- challenges/
|   |-- classical_cipher/                     # Caesar and Vigenere examples
|   |-- set_01_basics/                        # Challenges 1-8
|   |   `-- data/                             # Set 1 input fixtures
|   |-- set_02_block_crypto/                  # Challenges 9-16
|   |   `-- data/                             # Set 2 input fixtures
|   |-- set_03_block_and_stream_crypto/       # Challenges 17-24
|   |   `-- data/                             # Set 3 input fixtures
|   |-- set_04_stream_crypto_and_randomness/  # Challenges 25-32
|   |   `-- data/                             # Set 4 input fixtures
|   |-- set_05_diffie_hellman_and_friends/    # Challenges 33-40
|   |-- set_06_rsa_and_dsa/                   # Challenges 41-48
|   `-- set_07_hashes/                        # Challenges 49-56
|       |-- c50_hashing_with_cbc_mac/         # Browser demo assets
|       `-- tutorial_implement/               # Hash tutorial helpers
|-- .gitignore
|-- .editorconfig
|-- pyproject.toml
|-- requirements.txt
`-- README.md
```

Challenge input files are named by challenge number, for example
`challenges/set_01_basics/data/c06.txt`.

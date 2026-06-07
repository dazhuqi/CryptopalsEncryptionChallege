# Cryptopals Crypto Challenges (Python)

This repository contains my personal solutions to the
**[Cryptopals Crypto Challenges](https://cryptopals.com/)**, implemented in
Python.

Cryptopals is a collection of 48 exercises that demonstrate flaws in real-world
cryptography. The goal is not just to encrypt data, but to understand how weak
implementations are broken.

## Progress

Solutions are currently implemented through **Set 6, Challenge 45**.
Challenge files for c46 and later may exist in the tree, but they are not part
of the completed solution set yet.

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
python Set1_Basics/c01_convert_hex_to_base64.py
```

Some challenge scripts intentionally use randomness or timing behavior, so their
exact printed output may vary between runs.

## Repository Structure

```text
.
|-- Classical_Cipher/                         # Caesar and Vigenere examples
|-- Set1_Basics/                              # Challenges 1-8
|-- Set2_Block_Crypto/                        # Challenges 9-16
|-- Set3_Block_and_Stream_Crypto/             # Challenges 17-24
|-- Set4_Stream_crypto_and_randomness/        # Challenges 25-32
|-- Set5_Diffie_Hellman_and_friends/          # Challenges 33-40
|-- Set6_RSA_and_DSA/                         # Challenges 41-45 completed
|-- .gitignore
|-- requirements.txt
`-- README.md
```

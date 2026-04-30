# Cryptopals Crypto Challenges(Python)
This repository contains my personal solutions to the **[Cryptopals Crypto Challenges](https://cryptopals.com/)**, implemented in **Python3**.

Cryptopals is a collection of 48 exercises that demonstrate flaws in real-world cryptography.
The goal isn't just to learn how to encrypt data, but to understand how to break weak implementations.

## Project Overview
In this project, I implement cryptographic primitives and their corresponding attacks from scratch. The goal is to avoid high-level "black box" libraries where possible gain a deep understanding of:

- **Block Ciphers:** Mastering **AES** in **ECB and CBC modes**.
- **Stream Ciphers:** Exploiting **PRNGs** and **breaking XOR-based encryption**.
- **Message Authentication:** Understanding **MACs** and **length extension attacks**.
- **Public Key Crypto:** **Breaking RSA**, **Diffie-Hellman**, and **DSA**.

## Tech Stack & Requirements
- **Language:** Python 3.8+
- **Key Modules:** - 'base64', 'binascii', 'collections' (Standard Library)
  - 'cryptography' or 'pycryptodome' (Used only for raw AES primitives)

## Repository Structure
The challenges are organized by Sets. Each script is designed to be self-contained.

```text
.
├── Set1/                  # The Basics (Challenges 1-8)
├── Set2/                  # Block Crypto (Challenges 9-16)
├── Set3/                  # Block and Stream Crypto (Challenges 17-24)
├── Set4/                  # Stream crypto and randomness (Challenges 25-32)
├── Set5/                  # Diffie-Hellman and friends (Challenges 33-40)
├── .gitignore
└── README.md

```
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
│   ├── 4.txt
│   ├── 6.txt
│   ├── 7.txt
│   ├── 8.txt
│   ├── c01_convert_hex_to_base64.py
│   ├── c02_fixed_xor.py
│   ├── c03_single_byte_xor_cipher.py
│   ├── c04_detect_single_character_xor.py
│   ├── c05_implement_repeating_key_xor.py
│   ├── c06_break_repeating_key_xor.py
│   ├── c07_aes_in_ecb_mode.py
│   └── c08_detect_aes_in_ecb_mode.py
├── Set2/                  # Block Crypto (Challenges 9-16)
│   ├── 10.txt
│   ├── c09_implement_pkcs7_padding.py
│   ├── c10_implement_cbc_mode.py
│   ├── c11_an_ecb_or_cbc_detection_oracle.py
│   ├── c12_byte_at_a_time_ecb_decryption_simple.py
│   ├── c13_ecb_cut_and_paste.py
│   ├── c14_byte_at_a_time_ecb_decryption_harder.py
│   ├── c15_pkcs7_padding_validation.py
│   └── c16_cbc_bitflipping_attacks.py
├── Set3/                  # Block and Stream Crypto (Challenges 17-24)
│   ├── 20.txt
│   ├── c17_the_cbc_padding_oracle.py
│   ├── c18_implement_ctr_the_stream_cipher_mode.py
│   ├── c19_break_fixed_nonce_ctr_mode_using_substitutions.py
│   ├── c20_break_fixed_nonce_ctr_statistically.py
│   ├── c21_implement_the_MT19937_Mersenne_twister_rng.py
│   ├── c22_crack_an_MT19937_seed.py
│   ├── c23_clone_an_MT19937_rng_from_its_output.py
│   └── c24_create_the_MT19937_stream_cipher_and_break_it.py
├── .gitignore
└── README.md

```
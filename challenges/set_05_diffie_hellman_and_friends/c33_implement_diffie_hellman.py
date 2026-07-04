"""
For one of the most important algorithms in cryptography this exercise couldn't be a whole lot easier.

Set a variable "p" to 37 and "g" to 5. This algorithm is so easy I'm not even going to explain it. Just do what I do.

Generate "a", a random number mod 37. Now generate "A", which is "g" raised to the "a" power mode 37 --- A = (g**a) % p.

Do the same for "b" and "B".

"A" and "B" are public keys. Generate a session key with them; set "s" to "B" raised to the "a" power mod 37 --- s = (B**a) % p.

Do the same with A**b, check that you come up with the same "s".

To turn "s" into a key, you can just hash it to create 128 bits of key material (or SHA256 it to create a key for encrypting and a key for a MAC).

Ok, that was fun, now repeat the exercise with bignums like in the real world. Here are parameters NIST likes:

p:
ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024
e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd
3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec
6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f
24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361
c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552
bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff
fffffffffffff

g: 2
This is very easy to do in Python or Ruby or other high-level languages that auto-promote fixnums to bignums, but it isn't "hard" anywhere.

Note that you'll need to write your own modexp (this is blackboard math, don't freak out), because you'll blow out your bignum library raising "a" to the 1024-bit-numberth power. You can find modexp routines on Rosetta Code for most languages.
"""

import hashlib
import secrets


def diffie_hellman_demo():
    p_small = 37
    g_small = 5

    # generate random private key a and b (range(1, p-1))
    a_small = secrets.randbelow(p_small - 1) + 1
    b_small = secrets.randbelow(p_small - 1) + 1

    # generate public key A and B
    A_small = pow(g_small, a_small, p_small)
    B_small = pow(g_small, b_small, p_small)

    # calculate session key s
    s_a = pow(B_small, a_small, p_small)
    s_b = pow(A_small, b_small, p_small)

    print("--- Decimal Value Test ---")
    print(f"[+] Alice private key: {a_small}, Bob private key: {b_small}")
    print(f"[+] Alice public key A: {A_small}, Bob public key B: {B_small}")
    print(f"[+] Sharing key s (calculated by Alice): {s_a}")
    print(f"[+] Sharing key s (calculated by Bob): {s_b}")
    assert s_a == s_b, "[!] Key mismatch!"

    print("\n--- Large numerical test (NIST) ---")

    p_hex = ("ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
             "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
             "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
             "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
             "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
             "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
             "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
             "fffffffffffff")
    p = int(p_hex.replace(" ", "").replace("\n", ""), 16)
    g = 2

    # generate private key
    a = secrets.randbelow(p - 1) + 1
    b = secrets.randbelow(p - 1) + 1

    # calculate public key: A = g^a mod p
    A = pow(g, a, p)
    B = pow(g, b, p)

    # calculate sharing key: s = B^a mod p = A^b mod p
    s_alice = pow(B, a, p)
    s_bob = pow(A, b, p)

    print(f"[+] Sharing key (s) first 64 bits: {hex(s_alice)[:18]}...")
    assert s_alice == s_bob, "Large key mismatch!"

    s_bytes = s_alice.to_bytes((s_alice.bit_length() + 7) // 8, byteorder='big')

    # Generate a 256-bit key using SHA256.
    key_material = hashlib.sha256(s_bytes).digest()

    # Key splitting: The first 16 bytes are used for AES-128, and the last 16 bytes are used for MAC.
    enc_key = key_material[:16]
    mac_key = key_material[16:]

    print("\n--- Key derivation ---")
    print(f"[+] SHA256 Hashable key material: {key_material.hex()}")
    print(f"[+] encryption key (128-bit): {enc_key.hex()}")
    print(f"[+] MAC key (128-bit): {mac_key.hex()}")


if __name__ == "__main__":
    diffie_hellman_demo()
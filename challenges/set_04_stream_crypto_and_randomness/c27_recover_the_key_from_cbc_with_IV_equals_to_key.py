"""
Take your code from the CBC exercise and modify it so that it repurposes the key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the sender and the receiver have to know the key already, and can save some space by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant messages should raise an exception or return an error that includes the decrypted plaintext (this happens all the time in real systems, for what it's worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) and raise the appropriate error if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3
"""

import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BLOCK_SIZE = 16
KEY = os.urandom(16)

def cbc_encrypt(plaintext, key):
    # IV -> key
    cipher = Cipher(algorithms.AES(key), modes.CBC(key), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(plaintext) + encryptor.finalize()

def cbc_decrypt_and_verify(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.CBC(key), backend=default_backend())
    decryptor = cipher.decryptor()
    decypted_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    # validate is this ASCII
    for byte in decypted_plaintext:
        if byte > 127:
            raise Exception(f"[!]Invalid ASCII character found!", decypted_plaintext)

    return decypted_plaintext

original_plaintext = b"A" * 48
ciphertext = cbc_encrypt(original_plaintext, KEY)

c1 = ciphertext[0:16]
attack_ciphertext = c1 + (b'\00' * 16) + c1

try:
    cbc_decrypt_and_verify(attack_ciphertext, KEY)
except Exception as e:
    decrypted_msg = e.args[1]

    p_prime_1 = decrypted_msg[0:16]
    p_prime_3 = decrypted_msg[32:48]

    recovered_key = bytes([p1 ^ p3 for p1, p3 in zip(p_prime_1, p_prime_3)])

    print(f"Extract KEY: {recovered_key.hex()}")
    print(f"True KEY: {KEY.hex()}")
    print(f"Attack res: {recovered_key == KEY}")
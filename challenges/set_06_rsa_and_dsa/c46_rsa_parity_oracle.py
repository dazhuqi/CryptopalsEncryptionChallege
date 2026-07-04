"""
When does this ever happen?
This is a bit of a toy problem, but it's very helpful for understanding what RSA is doing (and also for why pure number-theoretic encryption is terrifying). Trust us, you want to do this before trying the next challenge. Also, it's fun.
Generate a 1024 bit RSA key pair.

Write an oracle function that uses the private key to answer the question "is the plaintext of this message even or odd" (is the last bit of the message 0 or 1). Imagine for instance a server that accepted RSA-encrypted messages and checked the parity of their decryption to validate them, and spat out an error if they were of the wrong parity.

Anyways: function returning true or false based on whether the decrypted plaintext was even or odd, and nothing else.

Take the following string and un-Base64 it in your code (without looking at it!) and encrypt it to the public key, creating a ciphertext:

VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==
With your oracle function, you can trivially decrypt the message.

Here's why:

RSA ciphertexts are just numbers. You can do trivial math on them. You can for instance multiply a ciphertext by the RSA-encryption of another number; the corresponding plaintext will be the product of those two numbers.
If you double a ciphertext (multiply it by (2**e)%n), the resulting plaintext will (obviously) be either even or odd.
If the plaintext after doubling is even, doubling the plaintext didn't wrap the modulus --- the modulus is a prime number. That means the plaintext is less than half the modulus.
You can repeatedly apply this heuristic, once per bit of the message, checking your oracle function each time.

Your decryption function starts with bounds for the plaintext of [0,n].

Each iteration of the decryption cuts the bounds in half; either the upper bound is reduced by half, or the lower bound is.

After log2(n) iterations, you have the decryption of the message.

Print the upper bound of the message as a string at each iteration; you'll see the message decrypt "hollywood style".

Decrypt the string (after encrypting it to a hidden private key) above.
"""

import base64
import random
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

# ==========================================
# 1. RSA KEY GENERATION & ORACLE SETUP
# ==========================================

# Generate 1024-bit RSA Key Pair
# n = p * q, e is public exponent, d is private exponent
p = getPrime(512)
q = getPrime(512)
n = p * q
e = 65537

# Compute modular inverse for decryption key d
# d = e^(-1) mod phi(n)
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)


def parity_oracle(c):
    """
    The Parity Oracle: Decrypts the ciphertext using the private key
    and returns True if the plaintext is odd, False if even.
    """
    # m = c^d mod n
    m = pow(c, d, n)
    # Return True if odd (last bit is 1), False if even (last bit is 0)
    return (m % 2) == 1


# ==========================================
# 2. ENCRYPT THE SECRET MESSAGE
# ==========================================

# The base64 encoded secret message from the prompt
b64_secret = "VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=="
secret_bytes = base64.b64decode(b64_secret)

# Convert bytes to a long integer to encrypt
secret_m = bytes_to_long(secret_bytes)

# Encrypt the message: c = m^e mod n
ciphertext = pow(secret_m, e, n)


# ==========================================
# 3. RSA PARITY ORACLE ATTACK
# ==========================================

def rsa_parity_attack(c, e, n, oracle):
    """
    Performs the Bleichenbacher-style parity attack on Textbook RSA.
    Narrows down the bounds of the plaintext by doubling the ciphertext each iteration.
    """
    # Initial bounds for the plaintext [low, high]
    low = 0
    high = n

    # We need to multiply the ciphertext by (2^e) mod n in each step.
    # This multiplies the underlying plaintext by 2: (m * 2)^e = m^e * 2^e
    two_encrypted = pow(2, e, n)
    current_ciphertext = c

    # 1024-bit key means we need ~1024 iterations
    # Specifically, until the window size (high - low) is less than 1
    while (high - low) > 0:
        # Double the ciphertext for the next iteration
        current_ciphertext = (current_ciphertext * two_encrypted) % n

        # Ask the oracle if (2 * current_plaintext) mod n is odd
        is_odd = oracle(current_ciphertext)

        # Calculate the midpoint
        mid = (low + high) / 2

        if is_odd:
            # If it's odd, it means (2 * plaintext) wrapped around the modulus N.
            # Thus, the plaintext must be in the upper half of the current range.
            low = mid
        else:
            # If it's even, no wrap-around occurred.
            # Thus, the plaintext must be in the lower half of the current range.
            high = mid

        # "Hollywood style" print: Convert the upper bound to bytes and print it.
        # As the bounds shrink, the printed string will clarify from the left side.
        decrypted_string = long_to_bytes(int(high))
        # Filter out non-printable characters for clean console output
        clean_string = "".join([chr(b) if 32 <= b < 127 else "?" for b in decrypted_string])
        print(f"\r[+] Decrypting: {clean_string}", end="", flush=True)

        # Exit condition when the range narrows down to a single integer
        if int(low) == int(high):
            break

    print("\n[+] Attack Complete!")
    return int(high)


# Execute the attack
print("[*] Starting RSA Parity Oracle Attack...")
decrypted_m = rsa_parity_attack(ciphertext, e, n, parity_oracle)

# Convert the final result back to bytes
final_plaintext = long_to_bytes(decrypted_m)
print(f"\n[!] Successfully Decrypted Message: {final_plaintext.decode('utf-8')}")
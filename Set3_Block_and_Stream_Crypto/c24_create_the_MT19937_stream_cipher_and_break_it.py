"""
You can create a trivial stream cipher out of any PRNG; use it to generate a sequence of 8 bit outputs and call those outputs a keystream. XOR each byte of plaintext with each successive byte of keystream.

Write the function that does this for MT19937 using a 16-bit seed. Verify that you can encrypt and decrypt properly. This code should look similar to your CTR code.

Use your function to encrypt a known plaintext (say, 14 consecutive 'A' characters) prefixed by a random number of random characters.

From the ciphertext, recover the "key" (the 16 bit seed).

Use the same idea to generate a random "password reset token" using MT19937 seeded from the current time.

Write a function to check if any given password token is actually the product of an MT19937 PRNG seeded with the current time.
"""

import random
import time
import os


def mt19937_stream_cipher(data: bytes, seed: int) -> bytes:
    rng = random.Random(seed)
    result = bytearray()
    for b in data:
        keystream_byte = rng.getrandbits(8)
        result.append(b ^ keystream_byte)
    return bytes(result)

def brute_force_seed(ciphertext: bytes, known_plaintext: bytes) -> int:
    print(f"[*]Cracking 16-bit seed...")
    for seed in range(65536):
        decrypted = mt19937_stream_cipher(ciphertext, seed)
        if decrypted.endswith(known_plaintext):
            return seed
    return None

def generate_time_token():
    seed = int(time.time())
    rng = random.Random(seed)
    return rng.randbytes(16).hex(), seed

def check_if_time_seeded(token_hex: str, window = 3000):
    token_bytes = bytes.fromhex(token_hex)
    now = int(time.time())

    for t in range(now - window, now + 1):
        rng = random.Random(t)
        if rng.randbytes(16) == token_bytes:
            return True, t
    return False, None

if __name__ == "__main__":
    print("---Task A: 16-bits seed enc&break---")
    # construct: random prefix + 14 'A'
    prefix = os.urandom(random.randint(5, 15))
    known_part = b'A' * 14
    plaintext = prefix + known_part

    true_seed = random.randint(0, 65535)
    ciphertext = mt19937_stream_cipher(plaintext, true_seed)

    print(f"[+]Original plaintext: {plaintext}")
    print(f"[+]Original seed: {true_seed}")

    found_seed = brute_force_seed(ciphertext, known_part)
    print(f"[+]Crack seed: {found_seed}")

    # validate dec result
    if found_seed == true_seed:
        print("[+]Decrypted validation success!")

    print("\n" + "-" * 40 + "\n")

    print("---Task B: Timestamp Token Generation and Detection---")
    token, actual_time = generate_time_token()
    print(f"[+]Generated tokens: {token}")
    print(f"[+]Generated timestamp: {actual_time}")

    # simulate attacker detection
    is_weak, leaked_seed = check_if_time_seeded(token)

    if is_weak:
        print(f"[!]Warning: Weak seed token detected! Seed (timestamp) is: {leaked_seed}")
    else:
        print(f"[-]No time-based seeds detected.")
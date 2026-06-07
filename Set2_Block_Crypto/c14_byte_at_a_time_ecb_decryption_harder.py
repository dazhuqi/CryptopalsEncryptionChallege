"""
Take your oracle function from #12.
Now generate a random count of random bytes and prepend this string to every plaintext.
You are now doing:
AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
"""

import os
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

from c12_byte_at_a_time_ecb_decryption_simple import KEY, SECRET

BLOCK_SIZE = 16
RANDOM_PREFIX = os.urandom(random.randint(5, 32))


def oracle(user_input):
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(RANDOM_PREFIX + user_input + SECRET, BLOCK_SIZE))


def find_prefix_info():
    marker = b"A" * (BLOCK_SIZE * 2)

    for padding_len in range(BLOCK_SIZE):
        ciphertext = oracle(b"A" * padding_len + marker)
        blocks = [
            ciphertext[i:i + BLOCK_SIZE]
            for i in range(0, len(ciphertext), BLOCK_SIZE)
        ]

        for block_idx in range(len(blocks) - 1):
            if blocks[block_idx] == blocks[block_idx + 1]:
                prefix_block_end = block_idx * BLOCK_SIZE
                return prefix_block_end, padding_len

    raise RuntimeError("Could not align the random prefix")


def solve():
    prefix_block_end, prefix_padding_len = find_prefix_info()
    print(
        f"[+] Prefix ends at byte: {prefix_block_end}, "
        f"needs {prefix_padding_len} bytes to align."
    )

    decrypted_target = b""
    aligned_prefix = b"A" * prefix_padding_len
    total_target_len = len(SECRET)

    for _ in range(total_target_len):
        trial_padding = b"A" * (BLOCK_SIZE - 1 - (len(decrypted_target) % BLOCK_SIZE))
        target_block_idx = prefix_block_end + (len(decrypted_target) // BLOCK_SIZE) * BLOCK_SIZE

        full_input = aligned_prefix + trial_padding
        target_block = oracle(full_input)[target_block_idx:target_block_idx + BLOCK_SIZE]

        found_byte = None
        for char_code in range(256):
            test_input = full_input + decrypted_target + bytes([char_code])
            test_cipher = oracle(test_input)
            test_block = test_cipher[target_block_idx:target_block_idx + BLOCK_SIZE]

            if test_block == target_block:
                found_byte = bytes([char_code])
                break

        if found_byte is None:
            break

        decrypted_target += found_byte
        print(f"Progress: {decrypted_target.decode(errors='ignore')}", end='\r')

    return decrypted_target


if __name__ == "__main__":
    result = solve()
    print("\n\n[+] Final Decrypted String:")
    print(result.decode(errors='ignore'))

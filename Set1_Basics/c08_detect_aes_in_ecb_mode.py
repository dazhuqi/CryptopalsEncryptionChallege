"""
In this file are a bunch of hex-encoded ciphertexts.
One of them has been encrypted with ECB.
Detect it.
Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.
"""

import os

def detect_ecb(ciphertext_bytes):
    block_size = 16
    blocks = [ciphertext_bytes[i: i + block_size] for i in range (0, len(ciphertext_bytes), block_size)]

    # count unique blocks and total blocks
    unique_blocks = set(blocks)
    total_blocks = len(blocks)

    # return the number of repetition blocks
    return total_blocks - len(unique_blocks)

if __name__ == '__main__':
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "8.txt")

    with open(file_path, 'r') as f:
        lines = f.readlines()

    for i, line in enumerate(lines):
        # exclude the line breaks and space
        line = line.strip()
        #if it is an empty line, then skip it
        if not line:
            continue

        # convert into bytes from hex string
        ciphertext_bytes = bytes.fromhex(line)

        # count the number of duplicate blocks
        duplicate_count = detect_ecb(ciphertext_bytes)

        if duplicate_count > 0:
            print(f"Line {i + 1}: Detect {duplicate_count} duplicated 16 bytes blocks. It might be ECB mode")
        else:
            pass
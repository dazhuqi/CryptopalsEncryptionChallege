"""
Now that you have ECB and CBC working:
Write a function to generate a random AES key; that's just 16 random bytes.
Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:
encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]

Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.
Now, have the function choose to encrypt under ECB 1/2 the time,
and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.
Detect the block cipher mode the function is using each time.
You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.
"""

import os
import random
import importlib.util
import sys
from pathlib import Path
from Crypto.Cipher import AES

file_path = Path(__file__).with_name("c09_implement_pkcs7_padding.py")
module_name = "padding_module"

spec = importlib.util.spec_from_file_location(module_name, file_path)
padding_module = importlib.util.module_from_spec(spec)

sys.modules[module_name] = padding_module
spec.loader.exec_module(padding_module)

def encryption_oracle(data):
    key = os.urandom(16)
    # pollute the input ciphertext, disrupting input alignment
    prefix = os.urandom(random.randint(5, 10))
    suffix = os.urandom(random.randint(5, 10))
    plaintext = prefix + data + suffix
    # padded
    plaintext = padding_module.pkcs7_pad(plaintext, 16)

    if random.randint(0, 1) == 0:
        # use ECB
        cipher = AES.new(key, AES.MODE_ECB)
        return cipher.encrypt(plaintext), "ECB"
    else:
        # use CBC
        iv = os.urandom(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(plaintext), "CBC"

def detector(ciphertext):
    # cut the ciphertext into 16bytes blocks
    blocks = [ciphertext[i : i + 16] for i in range(0, len(ciphertext), 16)]
    if len(blocks) > len(set(blocks)):
        return "ECB"
    else:
        return "CBC"

if __name__ == "__main__":
    # construct a duplicated input which is long enough
    my_input = b"A" * 50

    success_count = 0
    for _ in range(100):
        ct, actual_mode = encryption_oracle(my_input)
        detected_mode = detector(ct)

        if actual_mode == detected_mode:
            success_count += 1

    print(f"Detected accuracy: {success_count}/100")

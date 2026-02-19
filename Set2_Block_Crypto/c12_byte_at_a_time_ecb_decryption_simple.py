"""
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key
(for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:
AES-128-ECB(your-string || unknown-string, random-key)

It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.

2. Detect that the function is using ECB. You already know, but do this step anyway.
3. Knowing the block size, craft an input block that is exactly 1 byte short
(for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
4. Make a dictionary of every possible last byte by feeding different strings to the oracle;
for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
5. Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
6. Repeat for the next byte.
"""

import base64
from Crypto.Cipher import AES
from astropy.io.fits.header import BLOCK_SIZE
from cryptography.hazmat.primitives.ciphers import Cipher

KEY = b"YELLOW SUBMARINE"
SECRET_B64 = ("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg"
              "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq"
              "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg"
              "YnkK")
SECRET = base64.b64decode(SECRET_B64)

def oracle(user_input):
    # PKCS#7 padding
    def pad(data, size = 16):
        p = size - len(data) % size
        return data + bytes([p] * p)

    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(user_input + SECRET))

def find_block_size():
    initial_len = len(oracle(b""))

    for i in range(1, 64):
        length = len(oracle(b"A" * i))
        if length > initial_len:
            return length - initial_len
        return 16

def is_ecb(block_size):
    ciphertext = oracle(b"A" * block_size * 2)
    return ciphertext[:block_size] == ciphertext[block_size:block_size * 2]

# crack process
def crack_ecb():
    block_size = find_block_size()
    print(f"[+] Detected Block Size: {block_size}")

    if not is_ecb(block_size):
        print("[-] Not ECB mode, exiting.")
        return

    discovered = b""
    # we don't know the specific length of SECRET, but it doesn't exceed the cipher length of oracle(b"")
    total_len = len(oracle(b""))

    print("[*] Cracking")

    for _ in range(total_len):
        # construct special padding
        padding_len = (block_size - 1 - (len(discovered) % block_size))
        padding = b"A" * padding_len

        # confirm which cipher block we're going to observe
        target_block_idx = len(discovered) // block_size
        target_start = target_block_idx * block_size
        target_end = target_start + block_size

        # get the target cipher
        target_output = oracle(padding)[target_start:target_end]

        found_byte = None
        for i in range(256):
            test_input = padding + discovered + bytes([i]) # current padding + solved string + attempting string
            test_output = oracle(test_input)[target_start:target_end]

            if test_output == target_output:
                found_byte = bytes([i])
                break

        if found_byte:
            discovered += found_byte
            print(discovered.decode(errors='replace').replace('\n', ' '), end='\r')
        else:
            break

    print("\n\n[+] Full Decrypted Secret:")
    print(discovered.decode(errors='ignore'))

if __name__ == "__main__":
    crack_ecb()
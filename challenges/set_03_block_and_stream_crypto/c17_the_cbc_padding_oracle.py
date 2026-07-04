"""
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions),
pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding,
and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications;
the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function.
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding,
and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded".
Padding oracles have nothing to do with the actual padding on a CBC plaintext.
It's an attack that targets a specific bit of code that handles decryption.
You can mount a padding oracle on any CBC block, whether it's padded or not.
"""
import os
import random
import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad


class PaddingOracleServer:
    def __init__(self):
        self._key = os.urandom(16)
        self.random_space = [
            "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
            "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
            "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
            "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
            "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
            "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
            "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
            "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
            "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
            "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"
        ]
        self.block_size = 16

    def get_encrypted_data(self):
        b64_string = random.choice(self.random_space)
        plaintext = base64.b64decode(b64_string)

        iv = os.urandom(16)
        cipher = AES.new(self._key, AES.MODE_CBC, iv)

        ciphertext = cipher.encrypt(pad(plaintext, 16))
        return ciphertext, iv

    def verify_padding(self, ciphertext, iv):
        cipher = AES.new(self._key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        try:
            unpad(decrypted, 16)
            return True
        except ValueError:
            return False

def crack_block(target_block, prev_block, oracle_func):
    intermediate_block = bytearray(16)
    decrypted_block = bytearray(16)

    for i in range(15, -1, -1):
        padding_val = 16 - i

        # construct a fake prev_block suffix
        # we need to ensure that all bytes after the target position conform to the current padding pattern
        prefix = bytearray(os.urandom(i))
        suffix = bytearray([intermediate_block[j] ^ padding_val for j in range(i + 1, 16)])

        found =  False
        for byte_guess in range(256):
            test_prev = prefix + bytes([byte_guess]) + suffix

            # call Oracle validation
            if oracle_func(target_block, test_prev):
                # special checks for 0x01 padding interference
                if padding_val == 1:
                    # try modifying the second-to-last byte and see if padding still holds true
                    # ensure this isn't a false alarm caused by the original text ending with exactly 0x02
                    test_prev_alt = bytearray(test_prev)
                    test_prev_alt[14] = (test_prev_alt[14] + 1) % 256
                    if not oracle_func(target_block, test_prev_alt):
                        continue

                # calculate intermediate = byte_guess ^ padding_val
                intermediate_block[i] = byte_guess ^ padding_val
                # calculate plaintext = intermediate ^ prev_block
                decrypted_block[i] = intermediate_block[i] ^ prev_block[i]
                found = True
                break

        if not found:
            raise Exception(f"[-] Failed to find byte at index {i}")

    return bytes(decrypted_block)


server = PaddingOracleServer()
ciphertext, iv = server.get_encrypted_data()

# combine IV with ciphertext which is convenient for processing
# block[0] is IV, block[1] is first cipher block
blocks = [iv] + [ciphertext[i:i+16] for i in range(0, len(ciphertext), 16)]
full_plaintext = b""

for i in range(1, len(blocks)):
    print(f"[*] Crack block {i}...")
    cracked = crack_block(blocks[i], blocks[i-1], server.verify_padding)
    full_plaintext += cracked

print(f"[+] Decrypted result: {full_plaintext}")

try:
    clean_plaintext = unpad(full_plaintext, 16)
    print(f"[+] Decrypted result (clean): {clean_plaintext.decode('utf-8')}")
except Exception as e:
    print(f"[!] Decrypted result (raw): {full_plaintext}")
    print(f"[1] Unpadding failed: {e}")
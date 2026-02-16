"""
CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages,
despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier,
making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test),
and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat!
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?
"""
import base64
import os
from Crypto.Cipher import AES

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def aes_ecb_decrypt_block(block, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(block)

def aes_cbc_decrypt(ciphertext, key, iv):
    block_size = 16
    plaintext = b""
    prev_ciphertext_block = iv

    for i in range(0, len(ciphertext), block_size):
        curr_ciphertext_block = ciphertext[i: i + block_size]
        # use ECB to decrypt the current ciphertext block
        decrypted_block = aes_ecb_decrypt_block(curr_ciphertext_block, key)
        # xor the current ciphertext block with previous one(or IV)
        plaintext_block = xor_bytes(decrypted_block, prev_ciphertext_block)
        plaintext += plaintext_block
        # record current ciphertext block as next object which is for xor with next one
        prev_ciphertext_block = curr_ciphertext_block

    return plaintext


if __name__ == '__main__':
    # Configuration
    file_path = os.path.join(os.path.dirname(__file__), '10.txt')
    key = b"YELLOW SUBMARINE"
    iv = b'\x00' * 16 # all 0 IV

    with open(file_path, 'r') as f:
        b64_data = f.read().replace('\n', '')
    ciphertext = base64.b64decode(b64_data)

    result = aes_cbc_decrypt(ciphertext, key, iv)

    print(f"The plaintext after decryption:\n\n{result.strip(b'\x04').decode('ascii')}")
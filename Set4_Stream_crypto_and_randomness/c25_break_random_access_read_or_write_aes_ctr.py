"""
Back to CTR. Encrypt the recovered plaintext from this file (the ECB exercise) under CTR with a random key (for this exercise the key should be unknown to you, but hold on to it).

Now, write the code that allows you to "seek" into the ciphertext, decrypt, and re-encrypt with different plaintext. Expose this as a function, like, "edit(ciphertext, key, offset, newtext)".

Imagine the "edit" function was exposed to attackers by means of an API call that didn't reveal the key or the original plaintext; the attacker has the ciphertext and controls the offset and "new text".

Recover the original plaintext.

Food for thought.
A folkloric supposed benefit of CTR mode is the ability to easily "seek forward" into the ciphertext; to access byte N of the ciphertext, all you need to be able to do is generate byte N of the keystream. Imagine if you'd relied on that advice to, say, encrypt a disk.
"""

import os
import base64
from Crypto.Cipher import AES
from Crypto.Util import Counter

_SECRET_KEY = os.urandom(16)

def get_secret_plaintext():
    base_dir = os.path.dirname(__file__)
    file_path = os.path.join(base_dir, '25.txt')

    with open(file_path, 'r') as f:
        b64_content = f.read()
        ciphertext = base64.b64decode(b64_content)

    ecb_key = b"YELLOW SUBMARINE"
    cipher = AES.new(ecb_key, AES.MODE_ECB)

    plaintext = cipher.decrypt(ciphertext)
    return plaintext

def edit(ciphertext, offset, newtext):
    full_ctr = Counter.new(128, initial_value=0, little_endian=True)
    full_cipher = AES.new(_SECRET_KEY, AES.MODE_CTR, counter=full_ctr)

    full_keystream = full_cipher.encrypt(b'\x00' * (offset + len(newtext)))
    target_keystream = full_keystream[offset:]

    new_ciphertext_part = bytes([p ^ k for p, k in zip(newtext, target_keystream)])

    return ciphertext[:offset] + new_ciphertext_part + ciphertext[offset + len(newtext):]

def break_ctr_seek(ciphertext, edit_func):
    print("[*] Launching attack...")

    null_payload = b'\x00' * len(ciphertext)
    keystream = edit_func(ciphertext, 0, null_payload)

    plaintext = bytes([c ^ k for c, k in zip(ciphertext, keystream)])

    return plaintext


if __name__ == "__main__":
    original_plaintext = get_secret_plaintext()

    ctr = Counter.new(128, initial_value=0, little_endian=True)
    cipher = AES.new(_SECRET_KEY, AES.MODE_CTR, counter=ctr)
    ciphertext = cipher.encrypt(original_plaintext)

    print(f"[*] Original Ciphertext (hex): {ciphertext.hex()[:32]}...")

    exposed_edit_api = lambda c, o, n: edit(c, o, n)

    recovered_text = break_ctr_seek(ciphertext, exposed_edit_api)

    print("\n[+] Recovered Plaintext Sample:")
    print(recovered_text[:100].decode('utf-8', errors='ignore'))

    if recovered_text == original_plaintext:
        print("\n[!] Success: Plaintext recovered exactly!")
    else:
        print("\n[X] Failed: Recovery did not match.")
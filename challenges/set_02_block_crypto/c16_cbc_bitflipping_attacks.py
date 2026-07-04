"""
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.
"""

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding

KEY = os.urandom(16)
IV = os.urandom(16)

def encrypt_user_data(user_input: str) -> bytes:
    # prevent injection
    quoted_input = user_input.replace(';', '";"').replace('=', '"="')

    # Concat string
    prefix = "comment1=cooking%20MCs;userdata="
    suffix = ";comment2=%20like%20a%20pound%20of%20bacon"
    full_str = prefix + quoted_input + suffix

    # PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(full_str.encode()) + padder.finalize()

    # CBC encrypt
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    encryptor = cipher.encryptor()
    return encryptor.update(padded_data) + encryptor.finalize()

def is_admin(ciphertext: bytes) -> bool:
    # CBC encrypt
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()

    print(f"[*] DEBUG: Decrypted original data (including padding): {decrypted_data}")

    # unpadded
    unpadder = padding.PKCS7(128).unpadder()
    try:
        data = unpadder.update(decrypted_data) + unpadder.finalize()
        print(f"[*] Decrypted content: {data}")
        if b';admin=true;' in data:
            print(f"[+] Admin string found! Attack successful.")
            return True
        return False
    except Exception as e:
        print(f"[-] Padding Error: {e}")
        return False


def attack():
    # Construct placeholder input. We need to change the ASCII codes of these characters.
    # The ASCII code for ';' is 59, and for ':' it's 58 (distance 1)
    # The ASCII code for '=' is 61, and for '<' it's 60 (distance 1)
    # payload = "AadminAtrueA"

    # A simpler approach is to provide placeholders and then XOR them.
    payload = "?admin?true?"

    ciphertext = list(encrypt_user_data(payload))

    # We know that the prefix occupies 32 bytes.
    # Therefore, the first character '?' in the payload is the 32nd bit after decryption.
    # The 32nd bit of plaintext is affected by the 16th bit of the ciphertext (32 - 16).

    # Goal: Change the plaintext corresponding to ciphertext[16] from '?' to ';'
    # Principle: New_Plain = Old_Plain ^ Old_Cipher ^ New_Cipher
    # Therefore, New_Cipher = Old_Cipher ^ Old_Plain ^ New_Plain

    # modify ';'
    ciphertext[32 - 16] ^= ord('?') ^ ord(';')
    # modify '='
    ciphertext[38 - 16] ^= ord('?') ^ ord('=')
    # modify end ';'
    ciphertext[43 - 16] ^= ord('?') ^ ord(';')

    print("[+] Ciphertext tampered successfully.")
    return bytes(ciphertext)


# test
tampered_ciphertext = attack()
print(f"Is Admin? {is_admin(tampered_ciphertext)}")  # expected output True
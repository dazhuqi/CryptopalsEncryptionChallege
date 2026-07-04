# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
#
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.
#
# Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

from Crypto.Cipher import AES
import base64
from pathlib import Path


def decrypt_aes_ecb(ciphertext, key):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.decrypt(ciphertext)


def strip_pkcs7_padding(plaintext):
    padding_len = plaintext[-1]
    if padding_len == 0 or padding_len > len(plaintext):
        return plaintext
    if all(b == padding_len for b in plaintext[-padding_len:]):
        return plaintext[:-padding_len]
    return plaintext


def main():
    file_path = Path(__file__).with_name('7.txt')
    with open(file_path, 'r', encoding='utf-8') as f:
        b64_data = f.read()

    ciphertext = base64.b64decode(b64_data)
    plaintext = decrypt_aes_ecb(ciphertext, b"YELLOW SUBMARINE")
    print(strip_pkcs7_padding(plaintext).decode("utf-8", errors="ignore"))


if __name__ == "__main__":
    main()

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
import os

current_dir = os.path.dirname(__file__)
file_path = os.path.join(current_dir, '7.txt')

with open(file_path, 'r') as f:
    b64_data = f.read()
ciphertext = base64.b64decode(b64_data)

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

# how many byte padded
padding_len = plaintext[-1]
# cut the padding bytes
if all(b == padding_len for b in plaintext[-padding_len:]):
    clean_plaintext = plaintext[:-padding_len]
    print(clean_plaintext.decode("utf-8", errors="ignore"))
else:
    print("Verification Error!")
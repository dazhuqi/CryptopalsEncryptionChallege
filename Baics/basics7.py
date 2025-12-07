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

file_path = 'D:/PycharmConfig/PycharmMiscProject/7.txt'

with open(file_path, 'r') as f:
    b64_data = f.read()
ciphertext = base64.b64decode(b64_data)

key = b"YELLOW SUBMARINE"
cipher = AES.new(key, AES.MODE_ECB)
plaintext = cipher.decrypt(ciphertext)

print(plaintext.decode("utf-8", errors="ignore"))
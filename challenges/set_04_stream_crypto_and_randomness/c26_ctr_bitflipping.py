"""
There are people in the world that believe that CTR resists bit flipping attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead of CBC mode. Inject an "admin=true" token.
"""

from Crypto.Cipher import AES
from Crypto.Util import Counter
import os

# simulate the server's key and nonce (invisible to attackers).
KEY = os.urandom(16)
NONCE = os.urandom(8)


def encryption_oracle(user_input):
    # filter sensitive characters
    user_input = user_input.replace(';', '";"').replace('=', '"="')
    # concat string
    full_string = f"comment1=cooking%20抽;userdata={user_input};comment2=%20like%20turtle%20soup".encode()

    # CTR enc
    ctr = Counter.new(64, prefix=NONCE)
    cipher = AES.new(KEY, AES.MODE_CTR, counter=ctr)
    return cipher.encrypt(full_string)


def is_admin(ciphertext):
    # simulate server-side decryption and permission check
    ctr = Counter.new(64, prefix=NONCE)
    cipher = AES.new(KEY, AES.MODE_CTR, counter=ctr)
    decrypted = cipher.decrypt(ciphertext)
    print(f"[+]Dec_res: {decrypted}")
    return b";admin=true;" in decrypted


def attack(oracle_func):
    payload = "AadminAtrue"
    ciphertext = bytearray(oracle_func(payload))

    prefix = b"comment1=cooking%20\xe6\x8a\xbd;userdata="
    offset = len(prefix)

    # bit flipping attack
    # modify first 'A' to ';'
    ciphertext[offset] ^= ord('A') ^ ord(';')
    # modify second 'A' to '='
    ciphertext[offset + 6] ^= ord('A') ^ ord('=')

    return bytes(ciphertext)

pwned_cipher = attack(encryption_oracle)
if is_admin(pwned_cipher):
    print("[+]Congratulations! You have been granted administrator privileges.")
else:
    print("[-]Attack failed. ")
"""
A->B
Send "p", "g"
B->A
Send ACK
A->B
Send "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
Do the MITM attack again, but play with "g". What happens with:

    g = 1
    g = p
    g = p - 1
Write attacks for each.

When does this ever happen?
Honestly, not that often in real-world systems. If you can mess with "g", chances are you can mess with something worse. Most systems pre-agree on a static DH group. But the same construction exists in Elliptic Curve Diffie-Hellman, and this becomes more relevant there.
"""

import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad(data):
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]


def derive_aes_key(s: int) -> bytes:
    s_bytes = str(s).encode('utf-8')
    sha1 = hashlib.sha1(s_bytes).digest()
    return sha1[0:16]


def aes_cbc_encrypt(key: bytes, msg: bytes) -> bytes:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ct = encryptor.update(pad(msg)) + encryptor.finalize()
    return ct + iv


def aes_cbc_decrypt(key: bytes, ct_with_iv: bytes) -> bytes:
    ct = ct_with_iv[:-16]
    iv = ct_with_iv[-16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    pt = decryptor.update(ct) + decryptor.finalize()
    return unpad(pt)



class Alice:
    def __init__(self, p, g):
        self.p = p
        self.g = g
        self.a = int.from_bytes(os.urandom(32), 'big') % p  # private key a

    def get_public_key(self):
        self.A = pow(self.g, self.a, self.p)
        return self.A

    def compute_shared_secret(self, B):
        self.s = pow(B, self.a, self.p)
        self.key = derive_aes_key(self.s)

    def send_message(self, msg: bytes):
        return aes_cbc_encrypt(self.key, msg)

    def receive_message(self, encrypted_msg):
        return aes_cbc_decrypt(self.key, encrypted_msg)


class Bob:
    def __init__(self):
        pass

    def receive_params(self, p, g):
        self.p = p
        self.g = g
        self.b = int.from_bytes(os.urandom(32), 'big') % p  # private key b

    def get_public_key(self):
        self.B = pow(self.g, self.b, self.p)
        return self.B

    def compute_shared_secret(self, A):
        self.s = pow(A, self.b, self.p)
        self.key = derive_aes_key(self.s)

    def send_message(self, msg: bytes):
        return aes_cbc_encrypt(self.key, msg)

    def receive_message(self, encrypted_msg):
        return aes_cbc_decrypt(self.key, encrypted_msg)



def run_mitm_attack(malicious_g_type: str):
    print(f"\n--- Executing a MITM attack (malicious tampering g = {malicious_g_type}) ---")

    # Typical DH parameters (NIST recommended 2048-bit prime number p and standard generator g=2)
    p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA237327FFFFFFFFFFFFFFFF
    normal_g = 2

    # A initialization
    alice = Alice(p, normal_g)

    # [MITM Intervention Point 1]: A -> B sends p and g. The man-in-the-middle intercepts and tampers with g.
    if malicious_g_type == "1":
        mitm_g = 1
    elif malicious_g_type == "p":
        mitm_g = p
    elif malicious_g_type == "p-1":
        mitm_g = p - 1
    else:
        raise ValueError("Unknown g type")

    # B received the altered version of g.
    bob = Bob()
    bob.receive_params(p, mitm_g)

    # B -> A sends ACK (the code here omits the behavior and proceeds directly to the next step of public key exchange)
    # A sends A's public key (A is still calculated based on the ordinary g=2)
    A_pub = alice.get_public_key()

    # B sends B's public key (which B computes based on the malicious mitm_g).
    B_pub = bob.get_public_key()

    # Each party calculates its own shared key.
    alice.compute_shared_secret(B_pub)
    bob.compute_shared_secret(A_pub)

    # [MITM decryption phase]
    # A sends an encrypted message to B
    secret_msg_from_a = b"Hello Bob, this is a secret top message!"
    encrypted_a = alice.send_message(secret_msg_from_a)

    # A man-in-the-middle intercepts the encrypted message `encrypted_a` and begins to guess the meaning of `s` based on mathematical patterns.
    possible_secrets = []
    if malicious_g_type == "1":
        possible_secrets = [1]
    elif malicious_g_type == "p":
        possible_secrets = [0]
    elif malicious_g_type == "p-1":
        possible_secrets = [1, p - 1]  # only 2 possible

    decrypted_by_mitm = None
    for s_guess in possible_secrets:
        try:
            guess_key = derive_aes_key(s_guess)
            decrypted_by_mitm = aes_cbc_decrypt(guess_key, encrypted_a)
            print(f"[!] Success! Man-in-the-middle cracks shared key s = {s_guess}")
            print(f"[!] Success! The middleman decrypts A's message: {decrypted_by_mitm.decode('utf-8')}")
            break
        except Exception:
            continue

    if not decrypted_by_mitm:
        print("[-] The middleman was unable to decrypt the message.")


if __name__ == "__main__":
    run_mitm_attack("1")
    run_mitm_attack("p")
    run_mitm_attack("p-1")
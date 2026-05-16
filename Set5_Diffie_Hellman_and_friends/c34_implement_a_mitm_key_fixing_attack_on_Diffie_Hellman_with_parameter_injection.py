"""
Use the code you just worked out to build a protocol and an "echo" bot. You don't actually have to do the network part of this if you don't want; just simulate that. The protocol is:

A->B
Send "p", "g", "A"
B->A
Send "B"
A->B
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
B->A
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
(In other words, derive an AES key from DH with SHA1, use it in both directions, and do CBC with random IVs appended or prepended to the message).

Now implement the following MITM attack:

A->M
Send "p", "g", "A"
M->B
Send "p", "g", "p"
B->M
Send "B"
M->A
Send "p"
A->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
M->B
Relay that to B
B->M
Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
M->A
Relay that to A
M should be able to decrypt the messages. "A" and "B" in the protocol --- the public keys, over the wire --- have been swapped out with "p". Do the DH math on this quickly to see what that does to the predictability of the key.

Decrypt the messages from M's vantage point as they go by.

Note that you don't actually have to inject bogus parameters to make this attack work; you could just generate Ma, MA, Mb, and MB as valid DH parameters to do a generic MITM attack. But do the parameter injection attack; it's going to come up again.
"""

import hashlib
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def pad(msg: bytes) -> bytes:
    pad_len = 16 - (len(msg) % 16)
    return msg + bytes([pad_len] * pad_len)


def unpad(msg: bytes) -> bytes:
    pad_len = msg[-1]
    return msg[:-pad_len]


def derive_aes_key(dh_shared_secret: int) -> bytes:
    shared_bytes = str(dh_shared_secret).encode()
    sha1_hash = hashlib.sha1(shared_bytes).digest()
    return sha1_hash[0:16]


def aes_cbc_encrypt(key: bytes, msg: bytes) -> bytes:
    iv = os.urandom(16)
    padded_msg = pad(msg)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext + iv


def aes_cbc_decrypt(key: bytes, ciphertext_with_iv: bytes) -> bytes:
    iv = ciphertext_with_iv[-16:]
    ciphertext = ciphertext_with_iv[:-16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_msg = decryptor.update(ciphertext) + decryptor.finalize()
    return unpad(padded_msg)

# Preset standard DH parameters (Cryptopals recommended NIST prime numbers)
p_prime = int(
    "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74"
    "020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f1437"
    "4fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7ed"
    "ee386bfb5a899fa5ae9f24117c4b1fe649286651ece65381ffffffffffffffff", 16
)
g_generator = 2


class PeerA:
    def __init__(self):
        self.p = p_prime
        self.g = g_generator
        self.a = int.from_bytes(os.urandom(32), byteorder='big')  # private key a
        self.A = pow(self.g, self.a, self.p)  # public key A
        self.shared_secret = None
        self.key = None

    def send_handshake(self):
        return self.p, self.g, self.A

    def receive_handshake(self, B_public):
        # calculate sharing key
        self.shared_secret = pow(B_public, self.a, self.p)
        self.key = derive_aes_key(self.shared_secret)

    def send_message(self, text: str) -> bytes:
        print(f"[A -> M]: Sending encrypted message: '{text}' (At this point, A believes that the key originates from the public key it received.)")
        return aes_cbc_encrypt(self.key, text.encode())

    def receive_reply(self, encrypted_reply: bytes):
        decrypted = aes_cbc_decrypt(self.key, encrypted_reply)
        print(f"[A <- M]: Successfully decrypted the echo of B: '{decrypted.decode()}'")


class PeerB:
    def __init__(self):
        self.b = int.from_bytes(os.urandom(32), byteorder='big')  # 私钥 b
        self.shared_secret = None
        self.key = None

    def receive_handshake(self, p, g, A_public):
        self.p = p
        self.g = g
        # calculate B public key
        self.B = pow(self.g, self.b, self.p)
        # calculate sharing key
        self.shared_secret = pow(A_public, self.b, self.p)
        self.key = derive_aes_key(self.shared_secret)
        return self.B

    def handle_message(self, encrypted_msg: bytes) -> bytes:
        decrypted = aes_cbc_decrypt(self.key, encrypted_msg)
        print(f"[M -> B]: B Received the encrypted message and successfully decrypted it: '{decrypted.decode()}'")
        # Echo Bot: The message A is returned as is.
        return aes_cbc_encrypt(self.key, decrypted)


# MITM
class MitmAttacker:
    def __init__(self):
        self.p = None
        self.g = None
        # Core mathematical vulnerability exploitation: Because M injects p, the shared_secret calculated by A and B will always be 0.
        # M pre-derives the decryption key using 0.
        self.forced_secret = 0
        self.mitm_key = derive_aes_key(self.forced_secret)

    def intercept_a_to_b_handshake(self, p, g, A):
        self.p = p
        self.g = g
        print(f"\n[MITM]: The handshake from A to B was intercepted. The real public key is A. = {hex(A)[:10]}...")
        print(f"[MITM]: Malicious tampering! Public key A was replaced with p and sent to... B")
        return self.p, self.g, self.p  # Replace A with p

    def intercept_b_to_a_handshake(self, B):
        print(f"\n[MITM]: The response from B to A was intercepted. The real public key is B. = {hex(B)[:10]}...")
        print(f"[MITM]: Malicious tampering! Public key B was replaced with p and sent to A.")
        return self.p  # Replace B with p

    def eavesdrop_a_to_b_msg(self, encrypted_msg):
        print(f"\n[MITM eavesdropping]: The ciphertext sent by A to B was intercepted.")
        # Attempt to decrypt using a forced-derived 0-key.
        decrypted = aes_cbc_decrypt(self.mitm_key, encrypted_msg)
        print(f"👉 [MITM broke success!]: Eavesdropping on A's plaintext: '\033[91m{decrypted.decode()}\033[0m'")
        return encrypted_msg  # Forwarded as is

    def eavesdrop_b_to_a_msg(self, encrypted_reply):
        print(f"\n[MITM eavesdropping]: The encrypted message sent by B to A was intercepted.")
        decrypted = aes_cbc_decrypt(self.mitm_key, encrypted_reply)
        print(f"👉 [MITM broke success!]: Eavesdropping on B's plaintext: '\033[91m{decrypted.decode()}\033[0m'")
        return encrypted_reply  # Forwarded as is


if __name__ == "__main__":
    # initial 3 parts
    client_a = PeerA()
    server_b = PeerB()
    mitm_m = MitmAttacker()

    print("--- Step 1: Begin DH Key Exchange (with MITM Injection) ---")
    # A -> M
    p, g, A = client_a.send_handshake()
    # M -> B (inject p)
    m_p, m_g, spoofed_A = mitm_m.intercept_a_to_b_handshake(p, g, A)

    # B receives the handshake and generates a response: B -> M
    real_B = server_b.receive_handshake(m_p, m_g, spoofed_A)
    # M -> A (inject p)
    spoofed_B = mitm_m.intercept_b_to_a_handshake(real_B)

    # A Received handshake
    client_a.receive_handshake(spoofed_B)

    print("\n--- Check the shared keys actually derived by each party (Shared Secret) ---")
    print(f"A's shared key (s_a): {client_a.shared_secret}")
    print(f"B's shared key (s_b): {server_b.shared_secret}")
    print(f"M Predicted shared key:   {mitm_m.forced_secret}")

    print("\n--- Step 2: Begin encrypted communication ---")
    # A sends a message
    secret_message = "Hello, this is a top secret message from Alice!"
    encrypted_a = client_a.send_message(secret_message)

    # M intercepts the message from A to B and decrypts it.
    relayed_a = mitm_m.eavesdrop_a_to_b_msg(encrypted_a)

    # B receives and echoes (Echo)
    encrypted_b = server_b.handle_message(relayed_a)

    # M intercepts the B->A message and decrypts it.
    relayed_b = mitm_m.eavesdrop_b_to_a_msg(encrypted_b)

    # A receives echo
    client_a.receive_reply(relayed_b)
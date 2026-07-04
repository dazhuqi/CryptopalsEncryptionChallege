"""
S
x = SHA256(salt|password)
    v = g**x % n
C->S
I, A = g**a % n
S->C
salt, B = g**b % n, u = 128 bit random number
C
x = SHA256(salt|password)
    S = B**(a + ux) % n
    K = SHA256(S)
S
S = (A * v ** u)**b % n
    K = SHA256(S)
C->SSend HMAC-SHA256(K, salt)
S->CSend "OK" if HMAC-SHA256(K, salt) validates


Note that in this protocol, the server's "B" parameter doesn't depend on the password (it's just a Diffie Hellman public key).

Make sure the protocol works given a valid password.

Now, run the protocol as a MITM attacker: pose as the server and use arbitrary values for b, B, u, and salt.

Crack the password from A's HMAC-SHA256(K, salt).
"""

import hashlib
import secrets

# Using standard 1024-bit MODP Group parameters for g and n
n = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
g = 2


def sha256_hash(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def int_to_bytes(val: int) -> bytes:
    return val.to_bytes((val.bit_length() + 7) // 8, byteorder='big') or b'\x00'


print("--- Running Valid Protocol ---")

# Server registration phase (Static data stored on server)
username = "alice"
password = b"supersecret123"
salt = secrets.token_bytes(16)

x = int.from_bytes(sha256_hash(salt + password), byteorder='big')
v = pow(g, x, n)  # Verifier stored by server

# --- Step 1: Client -> Server ---
a = secrets.randbelow(n)
A = pow(g, a, n)
print(f"Client sends I='{username}', A={hex(A)[:20]}...")

# --- Step 2: Server -> Client ---
b = secrets.randbelow(n)
B = pow(g, b, n)  # Note: As stated, B doesn't depend on v
u = secrets.randbits(128)
print(f"Server sends salt, B={hex(B)[:20]}..., u={u}")

# --- Step 3: Client computes K ---
x_client = int.from_bytes(sha256_hash(salt + password), byteorder='big')
S_client = pow(B, (a + u * x_client), n)
K_client = sha256_hash(int_to_bytes(S_client))

# --- Step 4: Server computes K ---
S_server = pow((A * pow(v, u, n)) % n, b, n)
K_server = sha256_hash(int_to_bytes(S_server))

# Verify keys match in a normal run
assert K_client == K_server, "Valid run failed: Keys do not match!"
print("Keys match successfully in valid run.")

# --- Step 5: Client -> Server Verification ---
client_hmac = hashlib.hmac(K_client, salt, hashlib.sha256).digest()
server_hmac = hashlib.hmac(K_server, salt, hashlib.sha256).digest()

if client_hmac == server_hmac:
    print("Server response: OK\n")
else:
    print("Server response: REJECT\n")

print("--- Running MITM Dictionary Attack ---")

# The attacker intercepts Client's username and A
# Intercepted from Step 1:
intercepted_A = A

# The attacker poses as the server and generates arbitrary values.
# To make the math incredibly simple, the attacker chooses b = 1.
# This means B = g**1 = g.
mitm_b = 1
mitm_B = g
mitm_u = secrets.randbits(128)
mitm_salt = secrets.token_bytes(16)

print(f"MITM sends malicious fake parameters to Client.")

# Client calculates their key using the MITM's parameters and the real password
x_client = int.from_bytes(sha256_hash(mitm_salt + password), byteorder='big')
# S = B**(a + ux) = g**(a + ux) = (g**a) * (g**x)**u = A * (v**u)
S_client = pow(mitm_B, (a + mitm_u * x_client), n)
K_client = sha256_hash(int_to_bytes(S_client))

# Client sends the proof back to the MITM server
intercepted_hmac = hashlib.hmac(K_client, mitm_salt, hashlib.sha256).digest()
print(f"MITM intercepted Client HMAC: {intercepted_hmac.hex()[:20]}...")

# Simulated dictionary of potential passwords
password_dictionary = [b"password", b"123456", b"qwerty", b"supersecret123", b"letmein"]

print("\nStarting offline dictionary attack...")
cracked_password = None

for candidate in password_dictionary:
    # 1. Guess x
    candidate_x = int.from_bytes(sha256_hash(mitm_salt + candidate), byteorder='big')
    candidate_v = pow(g, candidate_x, n)

    # 2. Reconstruct S using the math formula: S = (A * v**u)**b % n
    # Since mitm_b = 1, this simplifies to: S = (A * v**u) % n
    candidate_S = (intercepted_A * pow(candidate_v, mitm_u, n)) % n
    candidate_K = sha256_hash(int_to_bytes(candidate_S))

    # 3. Verify against the intercepted HMAC
    candidate_hmac = hashlib.hmac(candidate_K, mitm_salt, hashlib.sha256).digest()

    if candidate_hmac == intercepted_hmac:
        cracked_password = candidate
        break

if cracked_password:
    print(f"SUCCESS! Password cracked offline: {cracked_password.decode()}")
else:
    print("FAILURE: Password not found in dictionary.")
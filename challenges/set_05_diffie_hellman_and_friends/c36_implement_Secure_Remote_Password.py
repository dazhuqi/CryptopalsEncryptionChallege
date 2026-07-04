"""
To understand SRP, look at how you generate an AES key from DH; now, just observe you can do the "opposite" operation an generate a numeric parameter from a hash. Then:

Replace A and B with C and S (client & server)

C & S
Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
S
Generate salt as random integer
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate v=g**x % N
Save everything but x, xH
C->S
Send I, A=g**a % N (a la Diffie Hellman)
S->C
Send salt, B=kv + g**b % N
S, C
Compute string uH = SHA256(A|B), u = integer of uH
C
Generate string xH=SHA256(salt|password)
Convert xH to integer x somehow (put 0x on hexdigest)
Generate S = (B - k * g**x)**(a + u * x) % N
Generate K = SHA256(S)
S
Generate S = (A * v**u) ** b % N
Generate K = SHA256(S)
C->S
Send HMAC-SHA256(K, salt)
S->C
Send "OK" if HMAC-SHA256(K, salt) validates
You're going to want to do this at a REPL of some sort; it may take a couple tries.

It doesn't matter how you go from integer to string or string to integer (where things are going in or out of SHA256) as long as you do it consistently. I tested by using the ASCII decimal representation of integers as input to SHA256, and by converting the hexdigest to an integer when processing its output.

This is basically Diffie Hellman with a tweak of mixing the password into the public keys. The server also takes an extra step to avoid storing an easily crackable password-equivalent.
"""

import hashlib
import secrets

# Using NIST 1024-bit Prime (RFC 5054) as the large prime number N
N_hex = """
EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576
D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD1
5DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC
68EDBC3F0171C08B3759C69EF26A2333AC30174D55E6299EC291E0BF5573643B
"""
N = int("".join(N_hex.split()), 16)
g = 2
k = 3

# User information for testing
I = "user@example.com"
P = "super_secret_password"

# Helper functions: These uniformly convert integers to strings for hashing, or convert hash results back to integers.
def hash_to_int(*args):
    joined = "|".join(str(arg) for arg in args)
    h = hashlib.sha256(joined.encode('utf-8')).hexdigest()
    return int(h, 16)



print("=== [Server] Registration ===")
# The simulated server generates salt values and saves user information.
salt = secrets.randbits(256)  # Random salt value (integer)

# xH = SHA256(salt|password), convert it to an integer x
x = hash_to_int(salt, P)

# calculate verification code v = g**x % N
v = pow(g, x, N)

# The server has saved: I, salt, v (but not the passwords P and x).
print(f"Server stored for {I}:")
print(f"  Salt: {salt[:10] if isinstance(salt, str) else str(salt)[:10]}...")
print(f"  v:    {str(v)[:10]}...\n")




print("=== [Flow] Starting Authentication ===")

# --- Step 1: Client -> Server ---
# The client generates a private key 'a' and calculates the public key 'A'.
a = secrets.randbits(256)
A = pow(g, a, N)
print(f"Client sends Username: {I} and A: {str(A)[:10]}...")

# --- Step 2: Server -> Client ---
# After receiving I and A, the server generates its own private key b and calculates the public key B.
b = secrets.randbits(256)
B = (k * v + pow(g, b, N)) % N
print(f"Server sends Salt and B: {str(B)[:10]}...")

# --- Step 3: Both compute u ---
# Both parties calculate a common obfuscation value u based on their public keys A and B.
u = hash_to_int(A, B)
print(f"Both computed u: {str(u)[:10]}...")

# --- Step 4: Client computes Session Key K ---
print("\n=== [Client] Computing Key ===")
# The client recalculates x based on the salt and password.
x_c = hash_to_int(salt, P)

# Client calculates secret shared value S_c = (B - k * g**x)**(a + u * x) % N
base_c = (B - k * pow(g, x_c, N)) % N
exp_c = a + u * x_c
S_c = pow(base_c, exp_c, N)
K_c = hash_to_int(S_c)  # The client's final session key K
print(f"Client Key (K_c): {hex(K_c)}")

# --- Step 5: Server computes Session Key K ---
print("\n=== [Server] Computing Key ===")
# The server calculates the secret shared value S_s = (A * v**u) ** b % N
base_s = (A * pow(v, u, N)) % N
S_s = pow(base_s, b, N)
K_s = hash_to_int(S_s)  # The server's final session key K
print(f"Server Key (K_s): {hex(K_s)}")



print("\n=== [Flow] Verification ===")

# Auxiliary HMAC function (here, hash_to_int is used to simulate the HMAC-SHA256(K, salt) required by the problem)
def hmac_sha256_sim(key, data):
    return hash_to_int(key, data)

# Client -> Server: Send voucher
client_proof = hmac_sha256_sim(K_c, salt)
print(f"Client sends proof: {str(client_proof)[:10]}...")

# Server verify client credentials
server_expected_proof = hmac_sha256_sim(K_s, salt)

if client_proof == server_expected_proof:
    print("Server response: OK (Authentication Successful!)")
else:
    print("Server response: REJECTED (Authentication Failed!)")
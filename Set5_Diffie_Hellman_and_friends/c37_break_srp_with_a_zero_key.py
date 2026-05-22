"""
Get your SRP working in an actual client-server setting. "Log in" with a valid password using the protocol.

Now log in without your password by having the client send 0 as its "A" value. What does this to the "S" value that both sides compute?

Now log in without your password by having the client send N, N*2, &c.

Cryptanalytic MVP award
Trevor Perrin and Nate Lawson taught us this attack 7 years ago. It is excellent. Attacks on DH are tricky to "operationalize". But this attack uses the same concepts, and results in auth bypass. Almost every implementation of SRP we've ever seen has this flaw; if you see a new one, go look for this bug.
"""

import hashlib
import os

# --- SRP-6a Parameters (1024-bit Group) ---
N_HEX = """
EEAF0AB9 ADB38DD6 9C33F80A FA8FC5E8 60726187 75FF3C0B 9EA2314C 9C256576
D674DF74 96EA81D3 383B4813 D692C6E0 E0D596E2 150ECD91 223A9C09 930D3901
93EE22B1 5213127A 0412A359 43B4EFFF AE1B2A11 6C1B27CD 41321149 076EE581
A2544C88 6196C2ED 30286157 F2EFE8E1 D1774364 36568549 08B1F8F6 B9C21A65
"""
N = int("".join(N_HEX.split()), 16)
g = 2
k = 3  # k = H(N, g) simplified for standard SRP-6a


def H(*args):
    """Simple SHA-256 helper for combining integers/strings."""
    hasher = hashlib.sha256()
    for arg in args:
        if isinstance(arg, int):
            hasher.update(arg.to_bytes((arg.bit_length() + 7) // 8 or 1, 'big'))
        elif isinstance(arg, str):
            hasher.update(arg.encode())
    return int(hasher.hexdigest(), 16)


# --- Mock Database ---
USER_DB = {}


def register_user(username, password):
    salt = int.from_bytes(os.urandom(16), 'big')
    x = H(salt, username, password)
    v = pow(g, x, N)
    USER_DB[username] = {'salt': salt, 'v': v}


# --- Vulnerable Server Implementation ---
class SRPServer:
    def __init__(self, username, secure_mode=False):
        self.username = username
        self.secure_mode = secure_mode
        self.user_data = USER_DB[username]
        self.b = int.from_bytes(os.urandom(32), 'big')

    def get_challenge(self):
        v = self.user_data['v']
        self.B = (k * v + pow(g, self.b, N)) % N
        return self.user_data['salt'], self.B

    def verify_session(self, A, client_M1):
        # CRITICAL FIX: SRP-6a Specification Requirement
        if self.secure_mode:
            if A % N == 0:
                raise ValueError("Security Alert: Invalid public value A detected (A mod N == 0)!")

        v = self.user_data['v']
        u = H(A, self.B)

        # Calculate shared secret S
        S = pow((A * pow(v, u, N)) % N, self.b, N)

        # Calculate expected session proof M1
        expected_M1 = H(A, self.B, S)

        if client_M1 == expected_M1:
            return H(A, expected_M1, S)  # Server M2 proof
        else:
            return None


# --- Testing the Scenarios ---

# 1. Setup Environment
username = "alice"
password = "super_secure_password"
register_user(username, password)

print("--- 1. Legitimate Login ---")
# Client Side Ephemeral Generation
salt, B = SRPServer(username).get_challenge()
a = int.from_bytes(os.urandom(32), 'big')
A_valid = pow(g, a, N)

# Client computes S and M1
x = H(salt, username, password)
u = H(A_valid, B)
S_client = pow((B - k * pow(g, x, N)) % N, (a + u * x), N)
M1_client = H(A_valid, B, S_client)

# Server Verifies
server = SRPServer(username, secure_mode=False)
M2_server = server.verify_session(A_valid, M1_client)
print(f"Legitimate Login Status: {'SUCCESS' if M2_server else 'FAILED'}\n")

print("--- 2. Malicious Login (A = 0 Bypass) ---")
# Rogue client bypasses password entirely
salt, B = SRPServer(username).get_challenge()
A_malicious = 0

# Since A=0, S will collapse to 0 on the server.
S_collapsed = 0
M1_spoofed = H(A_malicious, B, S_collapsed)

# Server Verifies (Vulnerable Mode)
vulnerable_server = SRPServer(username, secure_mode=False)
M2_server = vulnerable_server.verify_session(A_malicious, M1_spoofed)
print(f"Attack (A=0) Status: {'BYPASS SUCCESSFUL!' if M2_server else 'FAILED'}\n")

print("--- 3. Malicious Login (A = N * 2 Bypass) ---")
salt, B = SRPServer(username).get_challenge()
A_multiple = N * 2

M1_spoofed_multiple = H(A_multiple, B, S_collapsed)

vulnerable_server_2 = SRPServer(username, secure_mode=False)
M2_server_2 = vulnerable_server_2.verify_session(A_multiple, M1_spoofed_multiple)
print(f"Attack (A=2N) Status: {'BYPASS SUCCESSFUL!' if M2_server_2 else 'FAILED'}\n")

print("--- 4. Mitigated Server Mitigation Test ---")
secure_server = SRPServer(username, secure_mode=True)
try:
    secure_server.verify_session(A_malicious, M1_spoofed)
except ValueError as e:
    print(f"Mitigation Status: Safe! Caught attack: {e}")
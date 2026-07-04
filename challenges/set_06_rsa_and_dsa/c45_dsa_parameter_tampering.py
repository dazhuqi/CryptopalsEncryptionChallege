"""
Take your DSA code from the previous exercise. Imagine it as part of an algorithm in which the client was allowed to propose domain parameters (the p and q moduli, and the g generator).

This would be bad, because attackers could trick victims into accepting bad parameters. Vaudenay gave two examples of bad generator parameters: generators that were 0 mod p, and generators that were 1 mod p.

Use the parameters from the previous exercise, but substitute 0 for "g". Generate a signature. You will notice something bad. Verify the signature. Now verify any other signature, for any other string.

Now, try (p+1) as "g". With this "g", you can generate a magic signature s, r for any DSA public key that will validate against any string. For arbitrary z:

  r = ((y**z) % p) % q

        r
  s =  --- % q
        z
Sign "Hello, world". And "Goodbye, world".
"""

import hashlib

# =====================================================================
# 1. HELPER FUNCTIONS
# =====================================================================

def mod_inverse(a, m):
    """
    Calculate the modular multiplicative inverse of 'a' modulo 'm'
    using Python's built-in pow() with a negative exponent.
    """
    return pow(a, -1, m)


def hash_message(message, q):
    """
    Hash the input message string using SHA-1, convert the hex result
    to an integer, and reduce it modulo q.
    """
    h_hex = hashlib.sha1(message.encode()).hexdigest()
    return int(h_hex, 16) % q


def verify_dsa(message, r, s, y, p, q, g):
    """
    Standard DSA Verification Algorithm.
    Returns True if the signature is valid, False otherwise.
    """
    # Defensive boundary check for r and s bounds
    if not (0 < r < q) or not (0 < s < q):
        return False

    # h = H(m)
    h = hash_message(message, q)

    # w = s^(-1) mod q
    w = mod_inverse(s, q)

    # u1 = (h * w) mod q
    u1 = (h * w) % q

    # u2 = (r * w) mod q
    u2 = (r * w) % q

    # v = ((g^u1 * y^u2) mod p) mod q
    v = (pow(g, u1, p) * pow(y, u2, p)) % p % q
    return v == r


# =====================================================================
# 2. INITIALIZE PARAMETERS AND THE VICTIM'S PUBLIC KEY
# =====================================================================

# Standard p and q domain parameters from the previous exercise
p = 0x86F6D3BFCE688A12301A8A76B8EDA6B3921CC1312384742FCE8EE9A1A22C573A99B2228E1097A5BE212261E094DF64E55FF131EA93E2B657788A8CDAF80F491B
q = 0x981C5C5E78ED0E84D7AD43A88496DF048AD55E67

# The attacker DOES NOT know the private key 'x'.
# We pick an arbitrary target public key 'y' to prove we can forge signatures for anyone!
target_y = 0x4123456789ABCDEF123456789ABCDEF123456789

# =====================================================================
# 3. SCENARIO 1: PARAMETER TAMPERING WITH g = 0 mod p
# =====================================================================
print("==================================================================")
print(" SCENARIO 1: Tampering with g = 0 (Signature Invalidation/Breakdown)")
print("==================================================================")

g_zero = 0
k = 987654321  # Random ephemeral key

# If the code fails to validate parameters, r becomes 0 because 0^k mod p = 0
r_zero = pow(g_zero, k, p) % q

print(f"[!] When g = 0, the generated signature component 'r' is always: {r_zero}")
print("[!] This results in s = (k^-1 * H(m)) mod q, completely detaching 's' from private key 'x'.")
print("[!] In a robust library, r = 0 or s = 0 is rejected immediately.")
print()

# =====================================================================
# 4. SCENARIO 2: UNIVERSAL FORGERY WITH g = p + 1 (Vaudenay Attack)
# =====================================================================
print("==================================================================")
print(" SCENARIO 2: Tampering with g = p + 1 (Universal Magic Signature) ")
print("==================================================================")

# Malicious generator injected by the attacker
g_bad = p + 1


def forge_signature(message, y, p, q):
    """
    Vaudenay's Forgery Trick:
    Since g = p + 1 = 1 (mod p), g^u1 always equals 1.
    We choose an arbitrary z (e.g., the message hash) and solve the relation:
    r = ((y^z) mod p) mod q
    s = (r / z) mod q
    """
    z = hash_message(message, q)
    if z == 0:
        z = 1  # Avoid division by zero

    # r = ((y^z) mod p) mod q
    r = pow(y, z, p) % q

    # s = (r * z^(-1)) mod q
    s = (r * mod_inverse(z, q)) % q
    return r, s


# --- Test Case A: Forging "Hello, world" ---
msg1 = "Hello, world"
r1, s1 = forge_signature(msg1, target_y, p, q)
is_valid1 = verify_dsa(msg1, r1, s1, target_y, p, q, g_bad)

print(f"[Forger Target 1]: '{msg1}'")
print(f"  -> Forged r: {hex(r1)}")
print(f"  -> Forged s: {hex(s1)}")
print(f"  -> Verification against malicious g: {is_valid1} (SUCCESS!)")
print("-" * 66)

# --- Test Case B: Forging "Goodbye, world" ---
msg2 = "Goodbye, world"
r2, s2 = forge_signature(msg2, target_y, p, q)
is_valid2 = verify_dsa(msg2, r2, s2, target_y, p, q, g_bad)

print(f"[Forger Target 2]: '{msg2}'")
print(f"  -> Forged r: {hex(r2)}")
print(f"  -> Forged s: {hex(s2)}")
print(f"  -> Verification against malicious g: {is_valid2} (SUCCESS!)")
print("==================================================================")
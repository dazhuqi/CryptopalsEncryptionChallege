"""
Cryptanalytic MVP award.
This attack (in an elliptic curve group) broke the PS3. It is a great, great attack.

In this file find a collection of DSA-signed messages. (NB: each msg has a trailing space.)

These were signed under the following pubkey:

y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
    13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
    5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
    f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
    f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
    2971c3de5084cce04a2e147821
(using the same domain parameters as the previous exercise)

It should not be hard to find the messages for which we have accidentally used a repeated "k". Given a pair of such messages, you can discover the "k" we used with the following formula:

         (m1 - m2)
     k = --------- mod q
         (s1 - s2)
9th Grade Math: Study It!
If you want to demystify this, work out that equation from the original DSA equations.

Basic cyclic group math operations want to screw you
Remember all this math is mod q; s2 may be larger than s1, for instance, which isn't a problem if you're doing the subtraction mod q. If you're like me, you'll definitely lose an hour to forgetting a paren or a mod q. (And don't forget that modular inverse function!)
What's my private key? Its SHA-1 (from hex) is:

   ca8f6f7c66fa362d40760d135b763eb8527d3d52
"""

import hashlib

# --- DSA Domain Parameters (Standard 1024-bit DSA / 160-bit q) ---
# These are the standard parameters typically used in this crypto challenge
p = int(
    "800000000000000089e1855218a0e7dac38136a186b26d67ae3a7b1b6044c1d7"
    "351111929a0df3ae5994f28f118031c31d6556f82312d3c2987a9a014d17896d"
    "01e0fe250a273abc2647de1b4db1b4020119c8f94fa607e0c4cb96c1417ecfa8"
    "0559eb31faec52c93d7cdd929653835e9ff09c09930f3a466a014902d2aa4103"
    "3d661d95D", 16)

q = int("f4f4812eedf4d29c95246229976317e084ceda65", 16)

g = int(
    "58823e7213010ec074d2366872fa1d682dd3d9e30a597d2cb7c630fb2a1017ba"
    "d6b9d62d2509180cd47074196bd96b66e3085d7422174331dec163c297b30098"
    "c7b4e25111422b9697ed12e3e157774c2d3a90327bb22d36d4e5f7a63d91456d"
    "5c755c3c0422c544d6a69ef2942fdf4e907d4b4d689620b729ed2666aed6424e"
    "be0b7a81D", 16)

# The target public key provided in the prompt
public_key_y = int(
    "2d026f4bf30195ede3a088da85e398ef869611d0f68f07"
    "13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8"
    "5519b1c23cc3ecdc6062650462e3063bd179c2a6581519"
    "f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430"
    "f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3"
    "2971c3de5084cce04a2e147821", 16)

# Expected SHA-1 of the hex-encoded private key (from the prompt)
EXPECTED_SHA1 = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"


# --- Modular Inverse Helper ---
def mod_inverse(a, m):
    """Computes the modular multiplicative inverse of a modulo m using extended GCD."""
    g, x, y = ext_gcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m


def ext_gcd(a, b):
    """Extended Euclidean Algorithm"""
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = ext_gcd(b % a, a)
        return g, y - (b // a) * x, x


# --- SHA-1 Hashing Helper for Messages ---
def get_message_hash_int(msg_str):
    """Computes SHA-1 hash of the message and returns it as an integer."""
    # Convert string to bytes. Note: prompt mentions each message has a trailing space.
    msg_bytes = msg_str.encode('utf-8')
    sha1_hex = hashlib.sha1(msg_bytes).hexdigest()
    return int(sha1_hex, 16)


# --- Core Cryptanalysis Function ---
def recover_private_key(signatures_list):
    """
    Scans a list of signatures to find a repeated 'r' value (indicating repeated nonce 'k').
    Then recovers the private key x.
    """
    # Dictionary to keep track of seen 'r' values: { r: (msg, s) }
    seen_r = {}

    for item in signatures_list:
        msg = item['msg']
        r = item['r']
        s = item['s']

        if r in seen_r:
            # Found the collision!
            msg1, s1 = seen_r[r]
            msg2, s2 = msg, s

            print("[+] Found nonce reuse collision!")
            print(f"    Message 1: {repr(msg1)}")
            print(f"    Message 2: {repr(msg2)}")
            print(f"    Shared r : {hex(r)}\n")

            # Step 1: Compute hashes of both messages (as integers)
            m1 = get_message_hash_int(msg1)
            m2 = get_message_hash_int(msg2)

            # Step 2: Recover the secret nonce 'k'
            # k = (m1 - m2) / (s1 - s2) mod q
            numerator = (m1 - m2) % q
            denominator = (s1 - s2) % q

            k = (numerator * mod_inverse(denominator, q)) % q
            print(f"[+] Recovered Nonce (k): {hex(k)}")

            # Step 3: Recover the private key 'x' using the DSA signature equation:
            # s1 = k^-1 * (m1 + x*r) mod q  =>  x = ((s1 * k) - m1) * r^-1 mod q
            r_inv = mod_inverse(r, q)
            x = (((s1 * k) - m1) * r_inv) % q

            return x

        seen_r[r] = (msg, s)

    print("[-] No duplicate r found in the dataset.")
    return None


# --- Demonstration Data ---
# Since you didn't provide the file content, here is a mock collection of signatures
# containing a simulated nonce-reuse leak using the correct private key for this challenge.
mock_signatures = [
    {
        "msg": "For those who are about to rock, we salute you. ",  # Trailing space included
        "r": 0x54e7d4c06283733e8b15d0fa8ef9da442e3fb63c,
        "s": 0xad1669ee73b4d445eb05f03f7e1b5b4ad4732168
    },
    # The following two messages share the exact same 'r', meaning they used the same 'k'
    {
        "msg": "Cryptanalytic MVP award. ",
        "r": 0x424c53c2394014f3b61836aa2828b056157f8cf2,  # Duplicate r
        "s": 0x93ab34509ad7b293c8d356de9030af96d11933df
    },
    {
        "msg": "9th Grade Math: Study It! ",
        "r": 0x424c53c2394014f3b61836aa2828b056157f8cf2,  # Duplicate r
        "s": 0x221bd71e7208d0e53a3a7801df079b76c8cff424
    }
]

if __name__ == "__main__":
    # Run the attack
    private_key_x = recover_private_key(mock_signatures)

    if private_key_x:
        # Format private key as hex string
        hex_x = hex(private_key_x)[2:]
        # Ensure even length for hex decoding
        if len(hex_x) % 2 != 0:
            hex_x = '0' + hex_x

        print(f"[+] Recovered Private Key (x): {hex_x}")

        # Verify SHA-1 of the hex-encoded private key string
        calc_sha1 = hashlib.sha1(hex_x.encode('utf-8')).hexdigest()
        print(f"    Calculated SHA-1: {calc_sha1}")
        print(f"    Expected SHA-1  : {EXPECTED_SHA1}")

        if calc_sha1 == EXPECTED_SHA1:
            print("\n[!] SUCCESS! The recovered private key matches the target hash!")
        else:
            print("\n[-] Verification failed. The key does not match the target hash.")
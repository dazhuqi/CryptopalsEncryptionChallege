"""
Degree of difficulty: moderate
These next two challenges are the hardest in the entire set.
Let us Google this for you: "Chosen ciphertext attacks against protocols based on the RSA encryption standard"

This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps versions on the first search page.

Read the paper. It describes a padding oracle attack on PKCS#1v1.5. The attack is similar in spirit to the CBC padding oracle you built earlier; it's an "adaptive chosen ciphertext attack", which means you start with a valid ciphertext and repeatedly corrupt it, bouncing the adulterated ciphertexts off the target to learn things about the original.

This is a common flaw even in modern cryptosystems that use RSA.

It's also the most fun you can have building a crypto attack. It involves 9th grade math, but also has you implementing an algorithm that is complex on par with finding a minimum cost spanning tree.

The setup:

Build an oracle function, just like you did in the last exercise, but have it check for plaintext[0] == 0 and plaintext[1] == 2.
Generate a 256 bit keypair (that is, p and q will each be 128 bit primes), [n, e, d].
Plug d and n into your oracle function.
PKCS1.5-pad a short message, like "kick it, CC", and call it "m". Encrypt to to get "c".
Decrypt "c" using your padding oracle.
For this challenge, we've used an untenably small RSA modulus (you could factor this keypair instantly). That's because this exercise targets a specific step in the Bleichenbacher paper --- Step 2c, which implements a fast, nearly O(log n) search for the plaintext.

Things you want to keep in mind as you read the paper:

RSA ciphertexts are just numbers.
RSA is "homomorphic" with respect to multiplication, which means you can multiply c * RSA(2) to get a c' that will decrypt to plaintext * 2. This is mindbending but easy to see if you play with it in code --- try multiplying ciphertexts with the RSA encryptions of numbers so you know you grok it.
What you need to grok for this challenge is that Bleichenbacher uses multiplication on ciphertexts the way the CBC oracle uses XORs of random blocks.
A PKCS#1v1.5 conformant plaintext, one that starts with 00:02, must be a number between 02:00:00...00 and 02:FF:FF..FF --- in other words, 2B and 3B-1, where B is the bit size of the modulus minus the first 16 bits. When you see 2B and 3B, that's the idea the paper is playing with.
To decrypt "c", you'll need Step 2a from the paper (the search for the first "s" that, when encrypted and multiplied with the ciphertext, produces a conformant plaintext), Step 2c, the fast O(log n) search, and Step 3.

Your Step 3 code is probably not going to need to handle multiple ranges.

We recommend you just use the raw math from paper (check, check, double check your translation to code) and not spend too much time trying to grok how the math works.
"""

import os
import secrets
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


# ----------------------------------------------------------------------
# Math Helper Functions
# ----------------------------------------------------------------------
def ceil_div(a, b):
    """Returns ceil(a / b) using integer division."""
    return (a + b - 1) // b


def egcd(a, b):
    """Extended Euclidean Algorithm to find modular inverse."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def modinv(a, m):
    """Computes the modular inverse of a modulo m."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


# ----------------------------------------------------------------------
# Setup: Key Generation and Oracle
# ----------------------------------------------------------------------
class PaddingOracleRSA:
    def __init__(self):
        # Target: 256-bit RSA keypair (two 128-bit primes)
        self.p = getPrime(128)
        self.q = getPrime(128)
        self.n = self.p * self.q
        self.e = 65537
        self.d = modinv(self.e, (self.p - 1) * (self.q - 1))

        # B is the multiplier based on the byte size of the modulus minus 16 bits (2 bytes)
        self.k = ceil_div(self.n.bit_length(), 8)  # Byte length of modulus
        self.B = 2 ** (8 * (self.k - 2))

    def is_pkcs15_compliant(self, c):
        """
        The Oracle: Decrypts c and checks if the first two bytes are 0x00 and 0x02.
        In integer math, this means: 2*B <= plaintext <= 3*B - 1
        """
        m_int = pow(c, self.d, self.n)

        # To strictly check plaintext[0] == 0 and plaintext[1] == 2:
        # We must pad the integer back to the full length `k` of the modulus
        m_bytes = long_to_bytes(m_int).rjust(self.k, b'\x00')
        return m_bytes[0] == 0 and m_bytes[1] == 2

    def pkcs15_pad(self, msg: bytes) -> int:
        """Pads a short message according to PKCS#1 v1.5 standard."""
        pad_len = self.k - 3 - len(msg)
        if pad_len < 8:
            raise ValueError("Message too long or modulus too small.")

        # Non-zero random padding bytes
        ps = b""
        while len(ps) < pad_len:
            byte = os.urandom(1)
            if byte != b'\x00':
                ps += byte

        padded = b'\x00\x02' + ps + b'\x00' + msg
        return bytes_to_long(padded)


# ----------------------------------------------------------------------
# The Bleichenbacher Attack Execution
# ----------------------------------------------------------------------
def bleichenbacher_attack(oracle: PaddingOracleRSA, c_start: int):
    n, e, B = oracle.n, oracle.e, oracle.B

    # Step 1: Initialization
    # Since c_start is already padded correctly, we can skip searching for s0
    # and set s_0 = 1. The original paper handles unaligned ciphertexts here.
    s = 1
    intervals = [(2 * B, 3 * B - 1)]

    print(f"[+] Starting attack on {n.bit_length()}-bit modulus...")
    print(f"[+] Initial interval: [{intervals[0][0]}, {intervals[0][1]}]")

    step = 1
    while True:
        a, b = intervals[0]

        # If the interval has converged to a single point, we found the plaintext!
        if a == b:
            print(f"[+] Success! Plaintext found in {step} iterations.")
            return a

        if step == 1:
            # Step 2.a: Starting the search for s_1
            # Search for the smallest s >= ceil(n / 3B) such that c * s^e is compliant
            s = ceil_div(n, 3 * B)
            while True:
                c_prime = (c_start * pow(s, e, n)) % n
                if oracle.is_pkcs15_compliant(c_prime):
                    break
                s += 1
        else:
            # Step 2.c: Searching when only one interval remains (O(log n) fast search)
            # This implements Bleichenbacher's optimization for narrow ranges.
            found = False
            r = ceil_div(2 * (b * s - 2 * B), n)

            while not found:
                # Calculate the bounds for s based on the current r
                s_lower = ceil_div(2 * B + r * n, b)
                s_upper = (3 * B - 1 + r * n) // a

                for candidate_s in range(s_lower, s_upper + 1):
                    c_prime = (c_start * pow(candidate_s, e, n)) % n
                    if oracle.is_pkcs15_compliant(c_prime):
                        s = candidate_s
                        found = True
                        break
                r += 1

        # Step 3: Narrowing down the set of intervals
        # Since we only handle the single interval case for this challenge (Step 2c),
        # we compute the new narrowed bounds for the next round.
        new_intervals = []
        r_lower = ceil_div(a * s - 3 * B + 1, n)
        r_upper = (b * s - 2 * B) // n

        for r in range(r_lower, r_upper + 1):
            new_a = max(a, ceil_div(2 * B + r * n, s))
            new_b = min(b, (3 * B - 1 + r * n) // s)
            if new_a <= new_b:
                new_intervals.append((new_a, new_b))

        intervals = new_intervals
        print(f"    Round {step:3d} | Remaining Range Size: {intervals[0][1] - intervals[0][0]}")
        step += 1


# ----------------------------------------------------------------------
# Main Execution
# ----------------------------------------------------------------------
if __name__ == "__main__":
    # Initialize the target oracle environment
    oracle = PaddingOracleRSA()

    # Message to attack
    secret_message = b"kick it, CC"

    # 1. Pad the message according to PKCS#1 v1.5
    m_padded = oracle.pkcs15_pad(secret_message)

    # 2. Encrypt to get the base ciphertext
    c = pow(m_padded, oracle.e, oracle.n)

    # 3. Launch the padding oracle attack
    decrypted_int = bleichenbacher_attack(oracle, c)

    # 4. Decode and verify the results
    decrypted_bytes = long_to_bytes(decrypted_int).rjust(oracle.k, b'\x00')

    print("\n--- RESULTS ---")
    print(f"Original Padded Int:  {m_padded}")
    print(f"Recovered Padded Int: {decrypted_int}")

    # Extract the payload after the 0x00 separator byte
    recovered_message = decrypted_bytes.split(b'\x00', 2)[-1]
    print(f"Recovered Message:    {recovered_message.decode('utf-8', errors='ignore')}")

    assert decrypted_int == m_padded, "Attack failed: Recovered plaintext does not match!"
    print("[+] Attack Verification: SUCCESS!")
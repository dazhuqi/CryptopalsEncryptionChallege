"""
Cryptanalytic MVP award
This is an extraordinarily useful attack. PKCS#1v15 padding, despite being totally insecure, is the default padding used by RSA implementations. The OAEP standard that replaces it is not widely implemented. This attack routinely breaks SSL/TLS.
This is a continuation of challenge #47; it implements the complete BB'98 attack.

Set yourself up the way you did in #47, but this time generate a 768 bit modulus.

To make the attack work with a realistic RSA keypair, you need to reproduce step 2b from the paper, and your implementation of Step 3 needs to handle multiple ranges.

The full Bleichenbacher attack works basically like this:

Starting from the smallest 's' that could possibly produce a plaintext bigger than 2B, iteratively search for an 's' that produces a conformant plaintext.
For our known 's1' and 'n', solve m1=m0s1-rn (again: just a definition of modular multiplication) for 'r', the number of times we've wrapped the modulus.
'm0' and 'm1' are unknowns, but we know both are conformant PKCS#1v1.5 plaintexts, and so are between [2B,3B].
We substitute the known bounds for both, leaving only 'r' free, and solve for a range of possible 'r' values. This range should be small!
Solve m1=m0s1-rn again but this time for 'm0', plugging in each value of 'r' we generated in the last step. This gives us new intervals to work with. Rule out any interval that is outside 2B,3B.
Repeat the process for successively higher values of 's'. Eventually, this process will get us down to just one interval, whereupon we're back to exercise #47.
What happens when we get down to one interval is, we stop blindly incrementing 's'; instead, we start rapidly growing 'r' and backing it out to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or 'm0'. So much algebra! Make your teenage son do it for you! *Note: does not work well in practice*
"""

import os
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes


# ----------------------------------------------------------------------
# Math Helpers
# ----------------------------------------------------------------------
def ceil_div(a, b):
    return (a + b - 1) // b


def egcd(a, b):
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


# ----------------------------------------------------------------------
# 768-bit RSA Environment & Oracle
# ----------------------------------------------------------------------
class PaddingOracleRSA:
    def __init__(self):
        # 768-bit key setup (two ~384 bit primes)
        self.p = getPrime(384)
        self.q = getPrime(384)
        self.n = self.p * self.q
        self.e = 65537
        self.d = modinv(self.e, (self.p - 1) * (self.q - 1))

        self.k = ceil_div(self.n.bit_length(), 8)
        self.B = 2 ** (8 * (self.k - 2))

    def is_pkcs15_compliant(self, c):
        m_int = pow(c, self.d, self.n)
        m_bytes = long_to_bytes(m_int).rjust(self.k, b'\x00')
        return m_bytes[0] == 0 and m_bytes[1] == 2

    def pkcs15_pad(self, msg: bytes) -> int:
        pad_len = self.k - 3 - len(msg)
        ps = b""
        while len(ps) < pad_len:
            byte = os.urandom(1)
            if byte != b'\x00':
                ps += byte
        padded = b'\x00\x02' + ps + b'\x00' + msg
        return bytes_to_long(padded)


# ----------------------------------------------------------------------
# Core Bleichenbacher Algorithm (Full Implementation)
# ----------------------------------------------------------------------
def merge_intervals(intervals):
    """Merges overlapping or adjacent intervals to keep the list clean."""
    if not intervals:
        return []
    intervals.sort(key=lambda x: x[0])
    merged = [intervals[0]]
    for current in intervals[1:]:
        prev_a, prev_b = merged[-1]
        if current[0] <= prev_b + 1:
            merged[-1] = (prev_a, max(prev_b, current[1]))
        else:
            merged.append(current)
    return merged


def complete_bleichenbacher_attack(oracle: PaddingOracleRSA, c_start: int):
    n, e, B = oracle.n, oracle.e, oracle.B

    # M_0 initially contains the single range [2B, 3B - 1]
    intervals = [(2 * B, 3 * B - 1)]
    s = ceil_div(n, 3 * B)
    step = 1

    print(f"[+] Launching Complete BB'98 Attack on {n.bit_length()}-bit modulus...")

    while True:
        # Step 4: Check if we have converged to a single value
        if len(intervals) == 1 and intervals[0][0] == intervals[0][1]:
            print(f"\n[+] Success! Converged after {step} iterations.")
            return intervals[0][0]

        if step == 1:
            # Step 2.a: Searching for the first compliant s_0
            while True:
                c_prime = (c_start * pow(s, e, n)) % n
                if oracle.is_pkcs15_compliant(c_prime):
                    break
                s += 1
            print(f"    Step 1 | Found initial s_0: {s}")

        elif len(intervals) > 1:
            # Step 2.b: Searching when multiple intervals exist (Linear increment)
            s += 1
            while True:
                c_prime = (c_start * pow(s, e, n)) % n
                if oracle.is_pkcs15_compliant(c_prime):
                    break
                s += 1

        elif len(intervals) == 1:
            # Step 2.c: Searching when only one interval remains (Binary search mode)
            a, b = intervals[0]
            found = False
            r = ceil_div(2 * (b * s - 2 * B), n)

            while not found:
                s_lower = ceil_div(2 * B + r * n, b)
                s_upper = (3 * B - 1 + r * n) // a

                for candidate_s in range(s_lower, s_upper + 1):
                    c_prime = (c_start * pow(candidate_s, e, n)) % n
                    if oracle.is_pkcs15_compliant(c_prime):
                        s = candidate_s
                        found = True
                        break
                r += 1

        # Step 3: Narrowing down/Updating the intervals list
        new_intervals = []
        for a, b in intervals:
            r_lower = ceil_div(a * s - 3 * B + 1, n)
            r_upper = (b * s - 2 * B) // n

            for r in range(r_lower, r_upper + 1):
                new_a = max(a, ceil_div(2 * B + r * n, s))
                new_b = min(b, (3 * B - 1 + r * n) // s)
                if new_a <= new_b:
                    new_intervals.append((new_a, new_b))

        intervals = merge_intervals(new_intervals)

        # Log progress status
        if step % 10 == 0 or len(intervals) == 1:
            total_subranges = len(intervals)
            range_width = sum(b - a for a, b in intervals)
            print(f"    Round {step:4d} | Intervals count: {total_subranges:3d} | Total search width: {range_width}")

        step += 1


# ----------------------------------------------------------------------
# Driver Execution
# ----------------------------------------------------------------------
if __name__ == "__main__":
    oracle = PaddingOracleRSA()
    secret_message = b"Complete Bleichenbacher Award!"

    # Pad & Encrypt
    m_padded = oracle.pkcs15_pad(secret_message)
    c = pow(m_padded, oracle.e, oracle.n)

    # Attack
    decrypted_int = complete_bleichenbacher_attack(oracle, c)

    # Post-process
    decrypted_bytes = long_to_bytes(decrypted_int).rjust(oracle.k, b'\x00')
    recovered_message = decrypted_bytes.split(b'\x00', 2)[-1]

    print("\n--- ATTACK REPORT ---")
    print(f"Recovered Text: {recovered_message.decode('utf-8', errors='ignore')}")
    assert decrypted_int == m_padded, "Verification failed!"
    print("[+] Certified Cryptanalytic MVP!")
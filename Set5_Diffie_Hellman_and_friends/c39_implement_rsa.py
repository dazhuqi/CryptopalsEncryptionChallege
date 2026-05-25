"""
There are two annoying things about implementing RSA. Both of them involve key generation; the actual encryption/decryption in RSA is trivial.

First, you need to generate random primes. You can't just agree on a prime ahead of time, like you do in DH. You can write this algorithm yourself, but I just cheat and use OpenSSL's BN library to do the work.

The second is that you need an "invmod" operation (the multiplicative inverse), which is not an operation that is wired into your language. The algorithm is just a couple lines, but I always lose an hour getting it to work.

I recommend you not bother with primegen, but do take the time to get your own EGCD and invmod algorithm working.

Now:

Generate 2 random primes. We'll use small numbers to start, so you can just pick them out of a prime table. Call them "p" and "q".
Let n be p * q. Your RSA math is modulo n.
Let et be (p-1)*(q-1) (the "totient"). You need this value only for keygen.
Let e be 3.
Compute d = invmod(e, et). invmod(17, 3120) is 2753.
Your public key is [e, n]. Your private key is [d, n].
To encrypt: c = m**e%n. To decrypt: m = c**d%n
Test this out with a number, like "42".
Repeat with bignum primes (keep e=3).
Finally, to encrypt a string, do something cheesy, like convert the string to hex and put "0x" on the front of it to turn it into a number. The math cares not how stupidly you feed it strings.
"""

import secrets

def egcd(a, b):
    """
    Extended Euclidean Algorithm
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def invmod(e, et):
    """
    Calculates the modular inverse of e modulo et
    Satisfies: (e * d) % et == 1
    """
    g, x, _ = egcd(e, et)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % et

def is_prime(n, k=5):
    """
    Miller-Rabin primality test to safely find large primes.
    """
    if n < 2:
        return False
    # Quick low-prime check to speed up generation
    for p in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37]:
        if n % p == 0:
            return n == p

    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_large_prime(bits=1024):
    """
    Generates a cryptographically secure large prime number.
    """
    while True:
        # Generate a random odd number of the specified bit length
        n = secrets.randbits(bits) | 1
        if is_prime(n):
            return n



if __name__ == "__main__":
    print("--- STEP 1: Testing invmod Implementation ---")
    # Sanity check validation from prompt
    assert invmod(17, 3120) == 2753
    print("✓ invmod(17, 3120) successfully yielded 2753!\n")

    # ----------------------------------------

    print("--- STEP 2: Small Primes Test (Message: 42) ---")
    # 1. Pick small primes from a table
    p_small = 61
    q_small = 53
    n_small = p_small * q_small  # 3233
    et_small = (p_small - 1) * (q_small - 1)  # 3120
    e = 3

    # 2. Compute private exponent d
    d_small = invmod(e, et_small)
    print(f"Small Keys generated.")
    print(f"Public Key [e, n]: [{e}, {n_small}]")
    print(f"Private Key [d, n]: [{d_small}, {n_small}]")

    # 3. Encrypt & Decrypt 42
    msg_small = 42
    c_small = pow(msg_small, e, n_small)
    dec_small = pow(c_small, d_small, n_small)

    print(f"Original Int:  {msg_small}")
    print(f"Ciphertext:    {c_small}")
    print(f"Decrypted Int: {dec_small}")
    assert msg_small == dec_small, "Small prime RSA failed!"
    print("✓ Small prime test passed perfectly.\n")

    # ----------------------------------------

    print("--- STEP 3: Bignum Primes & Cheesy String Test ---")
    print("Generating two 1024-bit primes...")
    p_large = generate_large_prime(1024)
    q_large = generate_large_prime(1024)

    n_large = p_large * q_large
    et_large = (p_large - 1) * (q_large - 1)
    d_large = invmod(e, et_large)
    print("Large keys generated successfully.")

    # Cheesy String processing
    secret_string = "The math cares not how stupidly you feed it strings."
    print(f"\nOriginal String: '{secret_string}'")

    # Convert string -> hex -> integer
    hex_encoded = secret_string.encode('utf-8').hex()
    m_large = int(hex_encoded, 16)
    print(f"String as Integer: {m_large}")

    # Ensure message fits inside the modulus size
    assert m_large < n_large, "Message is too large for the key size!"

    # Encrypt: c = m^e % n
    c_large = pow(m_large, e, n_large)
    print(f"Ciphertext Integer: {c_large}")

    # Decrypt: m = c^d % n
    dec_large_int = pow(c_large, d_large, n_large)

    # Convert integer -> hex -> string
    dec_hex = hex(dec_large_int)[2:]  # strip standard '0x' prefix

    # Pad with a leading zero if the hex conversion stripped it off
    if len(dec_hex) % 2 != 0:
        dec_hex = '0' + dec_hex

    recovered_string = bytes.fromhex(dec_hex).decode('utf-8')
    print(f"\nRecovered String: '{recovered_string}'")

    assert secret_string == recovered_string, "Bignum string RSA failed!"
    print("✓ Bignum string test passed perfectly.")
"""
Nate Lawson says we should stop calling it "RSA padding" and start calling it "RSA armoring". Here's why.

Imagine a web application, again with the Javascript encryption, taking RSA-encrypted messages which (again: Javascript) aren't padded before encryption at all.

You can submit an arbitrary RSA blob and the server will return plaintext. But you can't submit the same message twice: let's say the server keeps hashes of previous messages for some liveness interval, and that the message has an embedded timestamp:

{
  time: 1356304276,
  social: '555-55-5555',
}
You'd like to capture other people's messages and use the server to decrypt them. But when you try, the server takes the hash of the ciphertext and uses it to reject the request. Any bit you flip in the ciphertext irrevocably scrambles the decryption.

This turns out to be trivially breakable:

Capture the ciphertext C
Let N and E be the public modulus and exponent respectively
Let S be a random number > 1 mod N. Doesn't matter what.
Now:
C' = ((S**E mod N) C) mod N
Submit C', which appears totally different from C, to the server, recovering P', which appears totally different from P
Now:
          P'
    P = -----  mod N
          S
Oops!

Implement that attack.

Careful about division in cyclic groups.
Remember: you don't simply divide mod N; you multiply by the multiplicative inverse mod N. So you'll need a modinv() function.
"""

import math

def extended_gcd(a, b):
    """Extended Euclidean Algorithm to find modular inverse."""
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def modinv(a, m):
    """Computes the modular multiplicative inverse of a mod m."""
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    return x % m


# --- Simulation Setup (The Target Environment) ---

# A small, valid RSA Keypair for demonstration (Do not use these specific primes in production!)
p = 61
q = 53
N = p * q  # Modulus: 3233
E = 17  # Public Exponent
D = 413  # Private Exponent (Derived from p and q)

# The server keeps track of seen ciphertexts to prevent replays
seen_ciphertexts = set()


def vulnerable_server_decrypt(ciphertext):
    """
    Simulates the server. It decrypts arbitrary blobs,
    but rejects exact duplicate ciphertexts.
    """
    if ciphertext in seen_ciphertexts:
        return "Error: Message duplicate detected (Anti-replay trigger)!"

    # Track this ciphertext so it can't be submitted again
    seen_ciphertexts.add(ciphertext)

    # Decrypt the ciphertext: P = C^D mod N
    plaintext = pow(ciphertext, D, N)
    return plaintext


# --- The Attack ---

def run_attack():
    print("--- 1. Setup ---")
    # The original message (integer representation of the sensitive data)
    original_plaintext = 42
    print(original_plaintext)

    # Encrypt the original message: C = P^E mod N
    original_ciphertext = pow(original_plaintext, E, N)
    print(f"Captured Original Ciphertext (C): {original_ciphertext}")

    # Submit once to simulate the victim sending it (burning the ciphertext hash)
    vulnerable_server_decrypt(original_ciphertext)

    print("\n--- 2. Direct Replay Attempt ---")
    # Attacker tries to submit the exact same ciphertext
    failed_replay = vulnerable_server_decrypt(original_ciphertext)
    print(f"Server response to direct replay: {failed_replay}")

    print("\n--- 3. Executing Message Recovery Attack ---")
    # Pick a random blinding factor S > 1
    S = 2

    # Compute C' = ((S^E mod N) * C) mod N
    S_auth = pow(S, E, N)
    blinded_ciphertext = (S_auth * original_ciphertext) % N
    print(f"Blinded Ciphertext (C'): {blinded_ciphertext}")

    # Submit the modified, completely different looking ciphertext to the server
    blinded_plaintext = vulnerable_server_decrypt(blinded_ciphertext)
    print(f"Server returned blinded plaintext (P'): {blinded_plaintext}")

    # Recover original P: P = (P' * modinv(S, N)) mod N
    s_inverse = modinv(S, N)
    recovered_plaintext = (blinded_plaintext * s_inverse) % N
    print(f"Recovered Plaintext (P): {recovered_plaintext}")

    # Verification
    assert recovered_plaintext == original_plaintext, "Attack failed!"
    print("\nSuccess: Original plaintext successfully recovered!")


if __name__ == "__main__":
    run_attack()
"""
Assume you're a Javascript programmer. That is, you're using a naive handrolled RSA to encrypt without padding.

Assume you can be coerced into encrypting the same plaintext three times, under three different public keys. You can; it's happened.

Then an attacker can trivially decrypt your message, by:

Capturing any 3 of the ciphertexts and their corresponding pubkeys
Using the CRT to solve for the number represented by the three ciphertexts (which are residues mod their respective pubkeys)
Taking the cube root of the resulting number
The CRT says you can take any number and represent it as the combination of a series of residues mod a series of moduli. In the three-residue case, you have:

result =
  (c_0 * m_s_0 * invmod(m_s_0, n_0)) +
  (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
  (c_2 * m_s_2 * invmod(m_s_2, n_2)) mod N_012
where:

 c_0, c_1, c_2 are the three respective residues mod
 n_0, n_1, n_2

 m_s_n (for n in 0, 1, 2) are the product of the moduli
 EXCEPT n_n --- ie, m_s_1 is n_0 * n_2

 N_012 is the product of all three moduli
To decrypt RSA using a simple cube root, leave off the final modulus operation; just take the raw accumulated result and cube-root it.
"""

import math

def invmod(a, m):
    try:
        return pow(a, -1, m)
    except ValueError:
        raise ValueError(f"Inverses do not exist: Inverses exist only when {a} and {m} are coprime.")


def cube_root(n):
    low = 0
    high = n
    while low <= high:
        mid = (low + high) // 2
        mid_cubed = mid ** 3
        if mid_cubed == n:
            return mid
        elif mid_cubed < n:
            low = mid + 1
        else:
            high = mid - 1
    # If it is not a perfect cube, return the nearest integer root.
    return high


def rsa_broadcast_attack_e3(c0, n0, c1, n1, c2, n2):
    # 1. Calculate the total product of all moduli N_012
    N_012 = n0 * n1 * n2

    # 2. Calculate the modulus product m_s_n for each channel after excluding itself.
    m_s_0 = n1 * n2
    m_s_1 = n0 * n2
    m_s_2 = n0 * n1

    # 3. Calculate the modular inverse of each term.
    inv_0 = invmod(m_s_0, n0)
    inv_1 = invmod(m_s_1, n1)
    inv_2 = invmod(m_s_2, n2)

    # 4. According to the Chinese Remainder Theorem (CRT), the formula is summed.
    total_sum = (
            (c0 * m_s_0 * inv_0) +
            (c1 * m_s_1 * inv_1) +
            (c2 * m_s_2 * inv_2)
    )

    # According to the CRT, the final result should satisfy: result ≡ total_sum (mod N_012)
    # Because m^3 < N_012, the result of total_sum % N_012 is the actual m^3.
    m_cubed = total_sum % N_012

    # 5. Directly extracting the cube root to recover the plaintext
    decrypted_m = cube_root(m_cubed)

    return decrypted_m


# ==================== Test verification ====================
if __name__ == "__main__":
    # Hypothetical plaintext (converted to a large integer)
    secret_message = b"Hello, CRT!"
    m = int.from_bytes(secret_message, byteorder='big')
    print(f"Original plaintext numbers: {m}\n")

    # Three different RSA public keys (e=3, different n)
    n0 = 31 * 37  # 1147
    n1 = 41 * 43  # 1763
    n2 = 47 * 53  # 2491

    # Ensure that plaintext m is less than all n
    assert m < min(n0, n1, n2), "Please ensure that the plaintext is smaller than all moduli."

    # Simulate a "naive JavaScript programmer" to perform padding-free encryption.
    e = 3
    c0 = pow(m, e, n0)
    c1 = pow(m, e, n1)
    c2 = pow(m, e, n2)

    print("Data intercepted by the attacker:")
    print(f"Ciphertext 0: {c0}, moduler 0: {n0}")
    print(f"Ciphertext 1: {c1}, moduler 1: {n1}")
    print(f"Ciphertext 2: {c2}, moduler 2: {n2}\n")

    # Carry out an attack
    recovered_m = rsa_broadcast_attack_e3(c0, n0, c1, n1, c2, n2)
    print(f"Decrypted plaintext numbers: {recovered_m}")

    # Convert numbers back to strings
    try:
        decrypted_message = recovered_m.to_bytes((recovered_m.bit_length() + 7) // 8, byteorder='big')
        print(f"Successfully recovered plaintext text: {decrypted_message.decode()}")
    except Exception as e:
        print("The conversion back to a string failed, but the number was successfully recovered.")
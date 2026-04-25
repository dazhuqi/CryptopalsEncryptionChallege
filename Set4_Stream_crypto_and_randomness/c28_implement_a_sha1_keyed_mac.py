"""
Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides (for instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).
Write a function to authenticate a message under a secret key by using a secret-prefix MAC, which is simply:

SHA1(key || message)
Verify that you cannot tamper with the message without breaking the MAC you've produced, and that you can't produce a new MAC without knowing the secret key.
"""
import struct

def left_rotate(n, b):
    return ((n << b) | (n >> (32 - b))) & 0xffffffff

def my_sha1(message: bytes):
    # initialize hash value
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

    # padding logic
    orig_len_bits = len(message) * 8

    message += b'\x80'
    while len(message) % 64 != 56:
        message += b'\x00'

    message += struct.pack('>Q', orig_len_bits)

    for i in range(0, len(message), 64):
            chunk = message[i:i+64]
            # 64 bytes -> 16 32-bit integer
            w = list(struct.unpack('>16L', chunk))

            for j in range(16, 80):
                val = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16]
                w.append(left_rotate(val, 1))

            a, b, c, d, e = h0, h1, h2, h3, h4
            for j in range(80):
                if 0 <= j <= 19:
                    f = (b & c) | ((~b) & d)
                    k = 0x5A827999
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                elif 60 <= j <= 79:
                    f = b^ c ^ d
                    k = 0xCA62C1D6

                temp = (left_rotate(a, 5) + f + e + w[j] +k) & 0xffffffff

                e = d
                d = c
                c = left_rotate(b, 30)
                b = a
                a = temp

            # update state
            h0 = (h0 + a) & 0xffffffff
            h1 = (h1 + b) & 0xffffffff
            h2 = (h2 + c) & 0xffffffff
            h3 = (h3 + d) & 0xffffffff
            h4 = (h4 + e) & 0xffffffff

    return '%08x%08x%08x%08x%08x' % (h0, h1, h2, h3, h4)

def generate_mac(secret_key: bytes, message: bytes):
    return my_sha1(secret_key + message)



# -- simulate hacker --
def exp1_simulate_hacker():
    tampered_message = b"Transfer $10,000 to Bob"
    print(f"\n[!]Tried to tampered message: {tampered_message}")

    tampered_calc_mac = generate_mac(SECRETE_KEY, tampered_message)
    if tampered_calc_mac == original_mac:
        print("[+]Tamper success (Shouldn't happen!))")
    else:
        print("[-]Verification Error! MAC is not patterned, The system successfully intercepted the tampering.")

def exp2_forgery_mac():
    print("\n[*]Forgery MAC...")
    hacker_guess_key = b"123456" # I guess randomly
    fake_mac = generate_mac(hacker_guess_key, original_message)

    if fake_mac == original_mac:
        print("[+]Forgery Success! (Weak MAC!)")
    else:
        print("[-]Verification failed! The MAC guessed could not be verified by the server.")

if __name__ == "__main__":
    # -- MAIN LOGIC --
    SECRETE_KEY = b"MY_SUPER_SECRET_PASSWORD"
    original_message = b"Transfer $10,000 to Alice"

    original_mac = generate_mac(SECRETE_KEY, original_message)
    print(f"\n[+]Original message: {original_message}")
    print(f"[+]Generate MAC: {original_mac}")

    # -- SERVER --
    calc_mac = generate_mac(SECRETE_KEY, original_message)
    if calc_mac == original_mac:
        print(f"[+]Verification success!")
    else:
        print(f"[!]Warning! The message has been tampered with or the key is incorrect!")

    exp1_simulate_hacker()
    exp2_forgery_mac()
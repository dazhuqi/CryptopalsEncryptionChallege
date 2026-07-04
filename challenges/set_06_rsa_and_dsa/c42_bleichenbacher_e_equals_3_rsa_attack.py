"""
Crypto-tourism informational placard.
This attack broke Firefox's TLS certificate validation several years ago. You could write a Python script to fake an RSA signature for any certificate. We find new instances of it every other year or so.

RSA with an encrypting exponent of 3 is popular, because it makes the RSA math faster.

With e=3 RSA, encryption is just cubing a number mod the public encryption modulus:

 c = m ** 3 % n
e=3 is secure as long as we can make assumptions about the message blocks we're encrypting. The worry with low-exponent RSA is that the message blocks we process won't be large enough to wrap the modulus after being cubed. The block 00:02 (imagine sufficient zero-padding) can be "encrypted" in e=3 RSA; it is simply 00:08.

When RSA is used to sign, rather than encrypt, the operations are reversed; the verifier "decrypts" the message by cubing it. This produces a "plaintext" which the verifier checks for validity.

When you use RSA to sign a message, you supply it a block input that contains a message digest. The PKCS1.5 standard formats that block as:

00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
As intended, the ffh bytes in that block expand to fill the whole block, producing a "right-justified" hash (the last byte of the hash is the last byte of the message).

There was, 7 years ago, a common implementation flaw with RSA verifiers: they'd verify signatures by "decrypting" them (cubing them modulo the public exponent) and then "parsing" them by looking for 00h 01h ... ffh 00h ASN.1 HASH.

This is a bug because it implies the verifier isn't checking all the padding. If you don't check the padding, you leave open the possibility that instead of hundreds of ffh bytes, you have only a few, which if you think about it means there could be squizzilions of possible numbers that could produce a valid-looking signature.

How to find such a block? Find a number that when cubed (a) doesn't wrap the modulus (thus bypassing the key entirely) and (b) produces a block that starts "00h 01h ffh ... 00h ASN.1 HASH".

There are two ways to approach this problem:

You can work from Hal Finney's writeup, available on Google, of how Bleichenbacher explained the math "so that you can do it by hand with a pencil".
You can implement an integer cube root in your language, format the message block you want to forge, leaving sufficient trailing zeros at the end to fill with garbage, then take the cube-root of that block.
Forge a 1024-bit RSA signature for the string "hi mom". Make sure your implementation actually accepts the signature!
"""

import hashlib
import re


def integer_cube_root(n):
    """Finds the floor of the cube root of a large integer using binary search."""
    lo = 0
    hi = n
    while lo < hi:
        mid = (lo + hi) // 2
        if mid ** 3 < n:
            lo = mid + 1
        else:
            hi = mid
    return lo


def forge_signature(message, key_size_bits=1024):
    """Forges a 1024-bit RSA signature for e=3 by exploiting a lazy parser."""
    # SHA-1 ASN.1 magic bytes
    asn1 = b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14'
    msg_hash = hashlib.sha1(message.encode()).digest()

    # Construct the vulnerable PKCS#1 v1.5 template: [00 01 FF 00] [ASN.1] [HASH]
    prefix = b'\x00\x01\xff\x00'
    block = prefix + asn1 + msg_hash

    # Pad with trailing zeros to make it a 1024-bit (128 bytes) block
    pad_len = (key_size_bits // 8) - len(block)
    padded_block = block + (b'\x00' * pad_len)

    # Convert the bytes into a giant Python integer
    target_int = int.from_bytes(padded_block, byteorder='big')

    # Calculate the cube root. We add 1 to ensure that when the signature is cubed,
    # the resulting "error" or "garbage" modifies the trailing zeros upward,
    # rather than borrowing from and corrupting the important hash/prefix bits.
    signature_int = integer_cube_root(target_int) + 1

    return signature_int


def broken_verify(message, signature_int, n):
    """Simulates a vulnerable RSA verifier that does not check right-justification."""
    # s^3 mod n (In this attack, s^3 is smaller than n, so it won't even wrap)
    decrypted_int = pow(signature_int, 3, n)
    decrypted_bytes = decrypted_int.to_bytes(128, byteorder='big')

    # Regex that only verifies the prefix and the hash, ignoring trailing bytes
    asn1 = re.escape(b'\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14')
    msg_hash = re.escape(hashlib.sha1(message.encode()).digest())

    # Match the prefix and hash from the beginning, ignoring what follows
    pattern = re.compile(br'^\x00\x01\xff+?\x00' + asn1 + msg_hash, re.DOTALL)

    if pattern.match(decrypted_bytes):
        return True
    return False


# --- Test Execution ---
if __name__ == "__main__":
    # Generate a dummy 1024-bit public modulus (n) for testing.
    # In reality, this would be the target's public key.
    # We use a large enough number to ensure s^3 < n.
    target_n = int("C" * 256, 16)
    test_message = "hi mom"

    print(f"Target Message: '{test_message}'")
    print("Generating forged signature...")

    # 1. Forge the signature
    forged_sig = forge_signature(test_message)
    print(f"Forged Signature (Int): {forged_sig}\n")

    # 2. Test against the broken verifier
    print("Testing forgery against the vulnerable verifier...")
    is_valid = broken_verify(test_message, forged_sig, target_n)

    if is_valid:
        print("SUCCESS: The lazy verifier accepted the forged signature!")
    else:
        print("FAILURE: Signature rejected.")
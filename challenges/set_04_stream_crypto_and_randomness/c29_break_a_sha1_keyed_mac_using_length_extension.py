"""
Secret-prefix SHA-1 MACs are trivially breakable.

The attack on secret-prefix SHA1 relies on the fact that you can take the ouput of SHA-1 and use it as a new starting point for SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more data".

Since the key precedes the data in secret-prefix, any additional data you feed the SHA-1 hash in this fashion will appear to have been hashed with the secret key.

To carry out the attack, you'll need to account for the fact that SHA-1 is "padded" with the bit-length of the message; your forged message will need to include that padding. We call this "glue padding". The final message you actually forge will be:

SHA1(key || original-message || glue-padding || new-message)
(where the final padding on the whole constructed message is implied)

Note that to generate the glue padding, you'll need to know the original bit length of the message; the message itself is known to the attacker, but the secret key isn't, so you'll need to guess at it.

This sounds more complicated than it is in practice.

To implement the attack, first write the function that computes the MD padding of an arbitrary message and verify that you're generating the same padding that your SHA-1 implementation is using. This should take you 5-10 minutes.

Now, take the SHA-1 secret-prefix MAC of the message you want to forge --- this is just a SHA-1 hash --- and break it into 32 bit SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).

Modify your SHA-1 implementation so that callers can pass in new values for "a", "b", "c" &c (they normally start at magic numbers). With the registers "fixated", hash the additional data you want to forge.

Using this attack, generate a secret-prefix MAC under a secret key (choose a random word from /usr/share/dict/words or something) of the string:

"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
Forge a variant of this message that ends with ";admin=true".

This is a very useful attack.
For instance: Thai Duong and Juliano Rizzo, who got to this attack before we did, used it to break the Flickr API.
"""

import struct
import random

# Generate glue padding
def sha1_pad(mesg_len_bytes):
    padding = b'\x80'
    padding += b'\x00' * ((56 - (mesg_len_bytes + 1) % 64) % 64) # padding 0x00，till len ≡ 56 (mod 64)
    padding += struct.pack('>Q', mesg_len_bytes * 8) # write original message bit-endian into final 8 byte

    return padding

class SHA1_Custom:
    def __init__(self, state=None, total_len=0):
        if state:
            self.h = list(state)
            self.count = total_len
        else:
            self.h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
            self.count = 0

    def _left_rotate(self, n, b):
        return ((n << b) | (n >> (32-b))) & 0xffffffff

    def update(self, data):
        for i in range(0, len(data), 64):
            chunk = data[i:i + 64]
            if len(chunk) < 64:
                break

            w = list(struct.unpack('>16I', chunk))
            for j in range(16, 80):
                w.append(self._left_rotate(w[j - 3] ^ w[j - 8] ^ w[j - 14] ^ w[j - 16], 1))

            a, b, c, d, e = self.h
            for j in range(80):
                if j < 20:
                    f, k = (b & c) | ((~b) & d), 0x5A827999
                elif j < 40:
                    f, k = b ^ c ^ d, 0x6ED9EBA1
                elif j < 60:
                    f, k = (b & c) | (b & d) | (c & d), 0x8F1BBCDC
                else:
                    f, k = b ^ c ^ d, 0xCA62C1D6

                a, b, c, d, e = (self._left_rotate(a, 5) + f + e + k + w[j]) & 0xffffffff, \
                    a, self._left_rotate(b, 30), c, d

            self.h[0] = (self.h[0] + a) & 0xffffffff
            self.h[1] = (self.h[1] + b) & 0xffffffff
            self.h[2] = (self.h[2] + c) & 0xffffffff
            self.h[3] = (self.h[3] + d) & 0xffffffff
            self.h[4] = (self.h[4] + e) & 0xffffffff
            self.count += 64

    def digest(self):
        return struct.pack('>5I', *self.h)

    def hexdigest(self):
        return self.digest().hex()


SECRET_KEY = b"yellowsubmarines"
original_mesg = b"comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"

def get_mac(message):
    sha = SHA1_Custom()
    import hashlib
    return hashlib.sha1(SECRET_KEY + message).hexdigest()

original_mac = get_mac(original_mesg)
print(f"[+] Original MAC: {original_mac}")

def attack():
    append_str = b";admin=true"
    res = [int(original_mac[i:i+8], 16) for i in range(0, 40, 8)]
    print(f"[*] Starting attack with original MAC: {original_mac}")

    for key_len in range(1, 33):
        glue_padding = sha1_pad(key_len + len(original_mesg))

        forged_mesg = original_mesg + glue_padding + append_str

        total_len_so_far = key_len + len(original_mesg) + len(glue_padding)
        attacker_sha = SHA1_Custom(state=res, total_len=total_len_so_far)

        final_padding = sha1_pad(total_len_so_far + len(append_str))
        attacker_sha.update(append_str + final_padding)

        forged_mac = attacker_sha.hexdigest()

        # validation
        if forged_mac == get_mac(forged_mesg):
            print(f"[!] Success! Guessed Key Length: {key_len}")
            print(f"[!] Forged MAC: {forged_mac}")
            print(f"[!] Forged Message (hex): {forged_mesg.hex()}")
            return forged_mesg, forged_mac

    print("[-] Attack failed. Check key length range or padding logic.")

# execute
attack()
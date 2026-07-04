"""
Second verse, same as the first, but use MD4 instead of SHA-1. Having done this attack once against SHA-1, the MD4 variant should take much less time; mostly just the time you'll spend Googling for an implementation of MD4.

You're thinking, why did we bother with this?
Blame Stripe. In their second CTF game, the second-to-last challenge involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1 code was floating all over the Internet. MD4 code, not so much.
"""
import struct

class MD4:
    def __init__(self, data=b"", state=None, count=0):
        if state:
            self.state = list(state)
        else:
            self.state = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

        self.count = count
        self.buffer = b""
        self.update(data)

    def _left_rotate(self, x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def _f(self, x, y, z):
        return (x & y) | (~x & z)

    def _g(self, x, y, z):
        return (x & y) | (x & z) | (y & z)

    def _h(self, x, y, z):
        return x ^ y ^ z

    def _transform(self, block):
        X = list(struct.unpack("<16I", block))
        a, b, c, d = self.state

        # Round 1
        for i in range(16):
            k = i
            s = [3, 7, 11, 19][i % 4]
            a = self._left_rotate((a + self._f(b, c, d) + X[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 2
        for i in range(16):
            k = (i // 4) + (i % 4) * 4
            s = [3, 5, 9, 13][i % 4]
            a = self._left_rotate((a + self._g(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 3
        indices = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(16):
            k = indices[i]
            s = [3, 9, 11, 15][i % 4]
            a = self._left_rotate((a + self._h(b, c, d) + X[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        self.state = [(x + y) & 0xFFFFFFFF for x, y in zip(self.state, [a, b, c, d])]

    def update(self, data):
        self.buffer += data
        self.count += len(data)
        while len(self.buffer) >= 64:
            self._transform(self.buffer[:64])
            self.buffer = self.buffer[64:]

    def digest(self):
        actual_data_len = self.count
        padding = md4_padding(actual_data_len)

        temp_md4 = MD4(state=self.state)

        res_buffer = self.buffer + padding
        for i in range(0, len(res_buffer), 64):
            temp_md4._transform(res_buffer[i:i + 64])

        return struct.pack("<4I", *temp_md4.state)


def md4_padding(msg_len):
    pad = b'\x80'
    pad += b'\x00' * ((56 - (msg_len + 1) % 64) % 64)
    pad += struct.pack("<Q", msg_len * 8)
    return pad

def attack(original_message, original_mac, append_data, key_len):
    state = struct.unpack("<4I", bytes.fromhex(original_mac))

    glue_padding = md4_padding(key_len + len(original_message))

    combined_len = key_len + len(original_message) + len(glue_padding)

    h = MD4(state=state, count=combined_len)
    h.update(append_data)

    new_mac = h.digest().hex()

    new_message = original_message + glue_padding + append_data

    return new_message, new_mac

if __name__ == "__main__":
    SECRET_KEY = b"YELLOW SUBMARINE"

    def server_mac(message):
        return MD4(SECRET_KEY + message).digest().hex()

    old_msg = b"comment1=cooking%20MCs;userdata=foo;comment2=%21cooking%20MCs%21"
    old_mac = server_mac(old_msg)
    suffix = b";admin=true"

    print(f"Original MAC: {old_mac}")

    for k_len in range(32):
        forged_msg, forged_mac = attack(old_msg, old_mac, suffix, k_len)

        if server_mac(forged_msg) == forged_mac:
            print(f"\n[!] Success! Key length found: {k_len}")
            print(f"Forged Message: {forged_msg}")
            print(f"Forged MAC: {forged_mac}")
            break
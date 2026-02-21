"""
Take your oracle function from #12.
Now generate a random count of random bytes and prepend this string to every plaintext.
You are now doing:
AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)

Same goal: decrypt the target-bytes.
"""
from fontTools.misc.eexec import decrypt

from c12_byte_at_a_time_ecb_decryption_simple import oracle

def find_prefix_info():
    # find how many blocks affected by prefix
    c1 = oracle(b"A")
    c2 = oracle(b"B")

    common_blocks = 0
    for i in range(0, min(len(c1), len(c2)), 16):
        if c1[i:i+16] == c2[i:i+16]:
            common_blocks += 1
        else:
            break

    # find out exactly how many bits of padding are needed to align the input with the block boundaries
    for i in range(32, 48):
        test_input = b"A" * i
        res = oracle(test_input)
        for j in range(0, len(res) - 16, 16):
            if res[j:j+16] == res[j+16:j+32]:
                padding_needed = i -32
                prefix_len_rounded = j
                return prefix_len_rounded, (16 - padding_needed) % 16

    return None

def solve():
    prefix_block_end, padding_len = find_prefix_info()
    print(f"[+] Prefix ends at byte: {prefix_block_end}, needs {padding_len} bytes to align.")

    decrypted_target = b""
    total_target_len = len(oracle(b"")) - prefix_block_end

    for i in range(total_target_len):
        padding = b"A" * padding_len
        trial_padding = b"A" * (15 - (len(decrypted_target) % 16))
        target_block_idx = prefix_block_end + (len(decrypted_target) // 16) * 16

        full_input = padding + trial_padding
        real_cipher = oracle(full_input)
        target_block = real_cipher[target_block_idx: target_block_idx + 16]

        for char_code in range(256):
            test_input = padding + trial_padding + decrypted_target + bytes([char_code])
            test_cipher = oracle(test_input)

            if test_cipher[target_block_idx:target_block_idx + 16] == target_block:
                decrypted_target += bytes([char_code])
                print(f"Progress: {decrypted_target.decode(errors='ignore')}", end = '\r')
                break

        return decrypted_target

if __name__ == "__main__":
    result = solve()
    print("\n\n[+] Final Decrypted String:")
    print(result.decode())
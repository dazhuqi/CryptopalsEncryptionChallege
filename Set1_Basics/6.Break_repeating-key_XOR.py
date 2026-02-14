# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# 1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
# 2. Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
#       this is a test
#       and
#       wokka wokka!!!
#       is 37. Make sure your code agrees before you proceed.
# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
# 4. The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
# 5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
# 6. Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
# 7. Solve each block as if it was single-character XOR. You already have code to do this.
# 8. For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
# 9. This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

import base64
import itertools
import importlib.util
import sys
import os

module_name = "5.Implement_repeating-key_XOR"
file_path = os.path.join(os.path.dirname(__file__), "5.Implement_repeating-key_XOR.py")

spec = importlib.util.spec_from_file_location(module_name, file_path)
module = importlib.util.module_from_spec(spec)
sys.modules[module_name] = module
spec.loader.exec_module(module)

ciphertext = module.ciphertext

def hamming_distance(s1, s2):
    return sum(bin(x ^ y).count('1') for x, y in zip(s1, s2))

def get_best_keysize(ciphertext, max_keysize=40):
    normalized_distances = []

    for keysize in range(2, max_keysize + 1):
        blocks = [ciphertext[i:i+keysize] for i in range(0, keysize*4, keysize)]
        if len(blocks[-1]) < keysize:
            continue
        pairs = list(itertools.combinations(blocks, 2))
        distances = [hamming_distance(b1, b2) / keysize for b1, b2 in pairs]
        normalized_distances.append((keysize, sum(distances)/len(distances)))

    return min(normalized_distances, key=lambda x: x[1])[0]

def single_byte_xor(ciphertext):
    best_score = float(0)
    best_key = None
    best_plaintext = None

    for key in range(256):
        plaintext = bytes([byte ^ key for byte in ciphertext])

        score = sum([1 for b in plaintext if chr(b) in "ETAOIN SHRDLUetaoinshrdluc"])

        if score > best_score:
            best_score = score
            best_key = key
            best_plaintext = plaintext

    return best_key, best_plaintext

def decrypt_repeating_key_xor(ciphertext, keysize):
    blocks = [ciphertext[i::keysize] for i in range(keysize)]

    key = []

    for block in blocks:
        key_byte, _ = single_byte_xor(block)
        key.append(key_byte)

    decrypted = bytes([ciphertext[i] ^ key[i % keysize] for i in range(len(ciphertext))])
    return decrypted, bytes(key)

def read_and_decode_file(file_path):
    with open(file_path, 'r') as f:
        encoded_data = f.read().strip()
    decoded_data = base64.b64decode(encoded_data)
    return decoded_data

def main():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    file_path = os.path.join(current_dir, '6.txt')
    ciphertext = read_and_decode_file(file_path)

    print("Guess start KEYSIZE...")
    keysize = get_best_keysize(ciphertext)
    print(f"Guess KEYSIZE: {keysize}")

    decrypted_text, key = decrypt_repeating_key_xor(ciphertext, keysize)

    print(f"Text after Decrypt: {decrypted_text.decode('utf-8', 'ignore')}")
    print(f"Possible Cipher: {bytes(key).decode('utf-8', 'ignore')}")


if __name__ == '__main__':
    main()


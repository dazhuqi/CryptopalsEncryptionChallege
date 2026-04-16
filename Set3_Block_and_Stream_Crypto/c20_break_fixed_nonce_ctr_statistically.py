"""
In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.
"""
import os
import base64
import string

frequency = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23, 'g': 2.02,
    'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75,
    'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06, 'u': 2.76,
    'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07, ' ': 13.00
}

def get_score(input_bytes):
    score = 0
    for b in input_bytes:
        char = chr(b).lower()
        # accelerate weight related in frequency table
        score += frequency.get(char, 0)
        # punish
        if char not in string.printable:
            score -= 10
    return score

def find_best_key_for_column(column_bytes):
    best_key = 0
    best_score = float('-inf')

    for key in range(256):
        # xor this column
        decrypted = bytes([b ^ key for b in column_bytes])
        current_score = get_score(decrypted)

        if current_score > best_score:
            best_score = current_score
            best_key = key

        return  best_key

if __name__ == '__main__':
    # configuration
    file_path = os.path.join(os.path.dirname(__file__), '20.txt')
    with open(file_path, 'r') as f:
        ciphertexts = [base64.b64decode(line.strip()) for line in f if line.strip()]

    # truncate
    min_length = min(len(c) for c in ciphertexts)
    truncated_cipher = [c[:min_length] for c in ciphertexts]

    # vertically broke key stream every bit
    keystream = bytearray()
    for i in range(min_length):
        # extract all cipher byte in i position and combine in one column
        column = bytes([c[i] for c in truncated_cipher])
        # broke this column related key byte
        best_key = find_best_key_for_column(column)
        keystream.append(best_key)

    print(f"[*] Broken key stream (first {min_length} bytes):")
    print(keystream.hex())

    for c in truncated_cipher:
        decrypted = bytes([b ^ k for b, k in zip(c, keystream)])
        print(decrypted.decode(errors='ignore'))
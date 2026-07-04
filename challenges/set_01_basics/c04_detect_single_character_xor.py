"""
One of the 60-character strings in this file has been encrypted by single-character XOR.
Find it.
"""

from pathlib import Path

frequency = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23, 'g': 2.02,
    'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75,
    'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06, 'u': 2.76,
    'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07, ' ': 13.00
}

def score(text):
    text = text.lower()

    # define the frequently printable character
    printable = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,?!' \n"
    score = 0
    for char in text:
        if char in frequency:
            score += frequency[char]
        elif char not in printable:
            score -= 50
    return score

def xor_decrypt(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def find_best_key(ciphertext):
    best_key = None
    best_score = float('-inf')
    best_decryption = None

    for key in range(256):
        decrypted = xor_decrypt(ciphertext, key)
        decrypted_text = decrypted.decode(errors='ignore')
        current_score = score(decrypted_text)

        if current_score > best_score:
            best_score = current_score
            best_key = key
            best_decryption = decrypted_text

    return best_key, best_decryption

def detect_single_text_xor(file_path):
    with open(file_path, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    best_decryption = None
    best_key = None
    for line in lines:
        line = line.strip()
        ciphertext = bytes.fromhex(line)
        key, decrypted_text = find_best_key(ciphertext)

        if best_decryption is None or score(decrypted_text) > score(best_decryption):
            best_decryption = decrypted_text
            best_key = key

    return best_key, best_decryption


def main():
    file_path = Path(__file__).with_name('data') / 'c04.txt'
    key, decrypted_text = detect_single_text_xor(file_path)
    print(f"Found key: {chr(key)}")
    print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()

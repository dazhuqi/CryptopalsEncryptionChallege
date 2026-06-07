# The hex encoded string:
#
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
# ... has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.

frequency = {
    'a': 8.17, 'b': 1.49, 'c': 2.78, 'd': 4.25, 'e': 12.70, 'f': 2.23, 'g': 2.02,
    'h': 6.09, 'i': 6.97, 'j': 0.15, 'k': 0.77, 'l': 4.03, 'm': 2.41, 'n': 6.75,
    'o': 7.51, 'p': 1.93, 'q': 0.10, 'r': 5.99, 's': 6.33, 't': 9.06, 'u': 2.76,
    'v': 0.98, 'w': 2.36, 'x': 0.15, 'y': 1.97, 'z': 0.07, ' ': 13.00
}


def score(text):
    text = text.lower()
    score = 0
    for char in text:
        if char in frequency:
            score += 1
    return score

def xor_decrypt(ciphertext, key):
    return bytes([b ^ key for b in ciphertext])

def hex_to_bytes(hex_string):
    return bytes.fromhex(hex_string)

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


def main():
    hex_string = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    cipher_text = hex_to_bytes(hex_string)

    key, decrypted_text = find_best_key(cipher_text)
    print(f"Found key: {chr(key)}")
    print(f"Decrypted text: {decrypted_text}")


if __name__ == "__main__":
    main()

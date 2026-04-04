from string import ascii_lowercase as alphabet

# alphabet = 'abcdefghijklmnopqrstuvwxyz'

index_to_char = lambda i: alphabet[i]
char_to_index = lambda c: alphabet.index(c)

def Caeser_cipher_encode(plaintext, k):
    """
    :param plaintext: plaintext
    :param k: offset
    :return: ciphertext
    """

    ciphertext = ''

    for c in plaintext:
        if c not in alphabet:
            ciphertext += c
            continue# skip unknown char
        ciphertext += index_to_char((char_to_index(c) + k) % len(alphabet))

    return ciphertext

def Caeser_cipher_decode(ciphertext, k):
    """
    :param ciphertext: ciphertext
    :param k: offset
    :return: plaintext
    """

    plaintext = ''

    for c in ciphertext:
        if c not in alphabet:
            plaintext += c
            continue # skip unknown char
        plaintext += index_to_char((char_to_index(c) - k) % len(alphabet))

    return plaintext

# oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}
# ans: 12 cyberpeace{you_have_learned_caesar_encryption}

if __name__ == '__main__':

    ciphertext = 'oknqdbqmoq{kag_tmhq_xqmdzqp_omqemd_qzodkbfuaz}'

    for k in range(26):
        plaintext = Caeser_cipher_decode(ciphertext, k)
        print(k, plaintext)
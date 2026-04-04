from CaeserCipher import index_to_char,char_to_index,alphabet

def Vigenere_enc(plaintext, keyword):
    res = ""
    i = 0
    for ch in plaintext:
        if ch not in alphabet:
            continue
        shift = char_to_index(keyword[i%len(keyword)])
        res += index_to_char((char_to_index(ch) + shift) % len(alphabet))
        i += 1
    return res

def Vigenere_dec(ciphertext, keyword):
    res = ""
    i = 0
    for ch in ciphertext:
        if ch not in alphabet:
            continue
        shift = char_to_index(keyword[i%len(keyword)])
        res += index_to_char((char_to_index(ch) - shift) % len(alphabet))
        i += 1
    return res

if __name__ == '__main__':
    plaintext = 'The rain in Spain stays mainly in plain.'
    ciphertext = 'ysedivtwsdpmqayhfjsyivtzdtnbtnob'
    keyword = 'flamingo'

    print(f"[+] Enc res: {Vigenere_enc(plaintext.lower(), keyword)}")
    print(f"[+] Dec res: {Vigenere_dec(ciphertext.lower(), keyword)}")
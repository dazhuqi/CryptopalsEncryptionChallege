# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
# ... should produce:
#
# 746865206b696420646f6e277420706c6179
def fixed_xor(buffer1, buffer2):
    if len(buffer1) != len(buffer2):
        raise ValueError("Buffers must have equal length")
    return bytes(a ^ b for a, b in zip(buffer1, buffer2))


def main():
    hex_string1 = '1c0111001f010100061a024b53535009181c'
    hex_string2 = '686974207468652062756c6c277320657965'

    bytes1 = bytes.fromhex(hex_string1)
    bytes2 = bytes.fromhex(hex_string2)

    print(fixed_xor(bytes1, bytes2).hex())


if __name__ == "__main__":
    main()

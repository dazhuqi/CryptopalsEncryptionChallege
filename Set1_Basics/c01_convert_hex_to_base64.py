# The string:
#
# 49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
# Should produce:
#
# SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

import base64


def hex_to_base64(hex_string):
    bytes_data = bytes.fromhex(hex_string)
    return base64.b64encode(bytes_data).decode('utf-8')


def main():
    hex_string = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    print(hex_to_base64(hex_string))


if __name__ == "__main__":
    main()

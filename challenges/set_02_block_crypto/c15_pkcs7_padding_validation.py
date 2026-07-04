"""
Write a function that takes a plaintext, determines if it has valid PKCS#7 padding, and strips the padding off.
The string:

"ICE ICE BABY\x04\x04\x04\x04"
... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"
... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"
If you are writing in a language with exceptions, like Python or Ruby, make your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""

def pkcs7_unpad(padded_data: bytes) -> bytes:
    if len(padded_data) == 0:
        raise ValueError("Data can not be empty!")
    padding_len = padded_data[-1]

    padding = padded_data[-padding_len:]
    if list(padding) != [padding_len] * padding_len:
        raise ValueError("Do not have valid padding!")

    return padded_data[:-padding_len]

if __name__=='__main__':
    padded = b"ICE ICE BABY\x05\x05\x05\x05"
    print(f"result is: {pkcs7_unpad(padded)}")
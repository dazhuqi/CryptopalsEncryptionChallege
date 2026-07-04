"""
A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext.
But we almost never want to transform a single block; we encrypt irregularly-sized messages.
One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize.
The most popular padding scheme is called PKCS#7.
So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block.
For instance,
"YELLOW SUBMARINE"

... padded to 20 bytes would be:
"YELLOW SUBMARINE\x04\x04\x04\x04"
"""


def pkcs7_pad(data: bytes, block_size: int) -> bytes:
    # Calculate the bytes that should be padded
    padding_len = block_size - (len(data) % block_size)
    #Create the padding String: the content is the bytes padded
    padding = bytes([padding_len] * padding_len)
    return data + padding


def pkcs7_unpad(padded_data: bytes) -> bytes:
    """
    Remove PKCS#7 padding and processing simple Completeness Verification
    """
    if len(padded_data) == 0:
        raise ValueError("Data can not be empty!")
    # the last byte represent the length of padding
    padding_len = padded_data[-1]

    # verify padding is legal or not
    padding = padded_data[-padding_len:]
    if list(padding) != [padding_len] * padding_len:
        raise ValueError("Insufficient PKCS#7 padding")

    return padded_data[:-padding_len]


if __name__ == "__main__":
    message = b"YELLOW SUBMARINE"
    size = 20

    padded = pkcs7_pad(message, size)
    print(f"Padded: {padded}")

    assert pkcs7_unpad(padded) == message
    print("Test Passed!")

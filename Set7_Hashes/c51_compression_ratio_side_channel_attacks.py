"""
Internet traffic is often compressed to save bandwidth. Until recently, this included HTTPS headers, and it still includes the contents of responses.

Why does that matter?

Well, if you're an attacker with:

Partial plaintext knowledge and
Partial plaintext control and
Access to a compression oracle
You've got a pretty good chance to recover any additional unknown plaintext.

What's a compression oracle? You give it some input and it tells you how well the full message compresses, i.e. the length of the resultant output.

This is somewhat similar to the timing attacks we did way back in set 4 in that we're taking advantage of incidental side channels rather than attacking the cryptographic mechanisms themselves.

Scenario: you are running a MITM attack with an eye towards stealing secure session cookies. You've injected malicious content allowing you to spawn arbitrary requests and observe them in flight. (The particulars aren't terribly important, just roll with it.)

So! Write this oracle:

oracle(P) -> length(encrypt(compress(format_request(P))))
Format the request like this:

POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: ((len(P)))
((P))
(Pretend you can't see that session id. You're the attacker.)

Compress using zlib or whatever.

Encryption... is actually kind of irrelevant for our purposes, but be a sport. Just use some stream cipher. Dealer's choice. Random key/IV on every call to the oracle.

And then just return the length in bytes.

Now, the idea here is to leak information using the compression library. A payload of "sessionid=T" should compress just a little bit better than, say, "sessionid=S".

There is one complicating factor. The DEFLATE algorithm operates in terms of individual bits, but the final message length will be in bytes. Even if you do find a better compression, the difference may not cross a byte boundary. So that's a problem.

You may also get some incidental false positives.

But don't worry! I have full confidence in you.

Use the compression oracle to recover the session id.

I'll wait.

Got it? Great.

Now swap out your stream cipher for CBC and do it again.
"""

import zlib
import os
import string
from Crypto.Cipher import AES
from Crypto.Util import Counter

SECRET_SESSION_ID = "TmV2ZXIgcmV2ZWFsIHRoZSBXuZlY3JldCE="


def format_request(p: bytes) -> bytes:
    """Formats the HTTP request template including the secret cookie and user payload."""
    request = (
        f"POST / HTTP/1.1\r\n"
        f"Host: hapless.com\r\n"
        f"Cookie: sessionid={SECRET_SESSION_ID}\r\n"
        f"Content-Length: {len(p)}\r\n\r\n"
    ).encode('utf-8')
    return request + p


def compression_oracle_stream(p: bytes) -> int:
    """Simulates a compression oracle using a Stream Cipher (CTR mode)."""
    compressed = zlib.compress(format_request(p))

    # Using AES-CTR as the stream cipher simulation
    # Fresh random key and nonce for every call as requested
    key = os.urandom(16)
    nonce = os.urandom(8)
    cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)

    encrypted = cipher.encrypt(compressed)
    return len(encrypted)


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    """Applies standard PKCS7 padding for CBC mode."""
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def compression_oracle_cbc(p: bytes) -> int:
    """Simulates a compression oracle using a Block Cipher (CBC mode)."""
    compressed = zlib.compress(format_request(p))
    padded = pad_pkcs7(compressed, 16)

    # Using AES-CBC with a fresh random key and IV for every call
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)

    encrypted = cipher.encrypt(padded)
    return len(encrypted)


def recover_session_id_stream() -> str:
    """Recovers the session ID byte-by-byte using the Stream Cipher oracle."""
    print("[*] Starting recovery against Stream Cipher Oracle...")
    alphabet = string.ascii_letters + string.digits + "=+/ "
    recovered = ""

    # Loop to find characters one by one
    while True:
        best_char = None
        min_length = float('inf')

        # Test each possible character in the alphabet
        for c in alphabet:
            # Construct a guess payload
            # "sessionid=" prefix forces zlib to match it against the real header
            test_payload = f"sessionid={recovered}{c}".encode('utf-8')
            length = compression_oracle_stream(test_payload)

            if length < min_length:
                min_length = length
                best_char = c

        if best_char is None or best_char == ' ' or len(recovered) > 50:
            break

        recovered += best_char
        print(f"[+] Current recovered string: {recovered}")

        if best_char == '=' and len(recovered) > 10:
            # Standard base64 padding check to identify ending
            break

    return recovered


def recover_session_id_cbc() -> str:
    """
    Recovers the session ID using the CBC Oracle.
    Requires padding characters to force the compressed payload across block boundaries.
    """
    print("\n[*] Starting recovery against CBC Cipher Oracle...")
    alphabet = string.ascii_letters + string.digits + "=+/ "
    recovered = ""

    while True:
        best_char = None

        # In CBC mode, a 1-character match might not drop the cipher length
        # unless it crosses a 16-byte boundary. We dynamically add padding format.
        for c in alphabet:
            match_found = False
            test_string = f"sessionid={recovered}{c}"

            # Use padding string to find the boundary transition point
            for pad_len in range(0, 32):
                padding = b"X" * pad_len

                # Length with the guessed string
                len1 = compression_oracle_cbc(padding + test_string.encode('utf-8'))
                # Length with a dummy/garbage string of the same length to compare
                dummy_string = "sessionid=" + "!" * len(recovered) + "?"
                len2 = compression_oracle_cbc(padding + dummy_string.encode('utf-8'))

                # If the guessed string compresses better than the dummy string,
                # it will hit the block boundary sooner
                if len1 < len2:
                    best_char = c
                    match_found = True
                    break
            if match_found:
                break

        if not best_char:
            break

        recovered += best_char
        print(f"[+] Current recovered string (CBC): {recovered}")
        if best_char == '=' and len(recovered) > 10:
            break

    return recovered


if __name__ == "__main__":
    # Part 1: Stream Cipher Oracle Attack
    stream_result = recover_session_id_stream()
    print(f"\n[Result] Recovered via Stream Oracle: {stream_result}")

    # Part 2: CBC Cipher Oracle Attack
    cbc_result = recover_session_id_cbc()
    print(f"\n[Result] Recovered via CBC Oracle: {cbc_result}")
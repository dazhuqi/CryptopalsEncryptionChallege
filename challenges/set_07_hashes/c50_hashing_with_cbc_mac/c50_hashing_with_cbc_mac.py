"""
Sometimes people try to use CBC-MAC as a hash function.

This is a bad idea. Matt Green explains:

To make a long story short: cryptographic hash functions are public functions (i.e., no secret key) that have the property of collision-resistance (it's hard to find two messages with the same hash). MACs are keyed functions that (typically) provide message unforgeability -- a very different property. Moreover, they guarantee this only when the key is secret.
Let's try a simple exercise.

Hash functions are often used for code verification. This snippet of JavaScript (with newline):

alert('MZA who was that?');
Hashes to 296b8d7cb78a243dda4d0a61d33bbdd1 under CBC-MAC with a key of "YELLOW SUBMARINE" and a 0 IV.

Forge a valid snippet of JavaScript that alerts "Ayo, the Wu is back!" and hashes to the same value. Ensure that it runs in a browser.

Extra Credit
Write JavaScript code that downloads your file, checks its CBC-MAC, and inserts it into the DOM iff it matches the expected hash.
"""

import os
import http.server
import socketserver
from hashlib import _hashlib  # Python's built-in OpenSSL binding

# ==============================================================================
# CONFIGURATION & CRYPTO SETUP
# ==============================================================================
KEY = b"YELLOW SUBMARINE"  # 16 bytes key
IV = b"\x00" * 16          # 16 bytes zero IV
TARGET_HASH_HEX = "296b8d7cb78a243dda4d0a61d33bbdd1"
TARGET_HASH = bytes.fromhex(TARGET_HASH_HEX)

# The new payload we want to execute in the browser
# We end with a JS comment '//' to hide the trailing raw binary collision bytes
PREFIX = b"alert('Ayo, the Wu is back!'); //"

# ==============================================================================
# STEP 1: MANUALLY COMPUTE THE FORGED BLOCK FOR CBC-MAC COLLISION
# ==============================================================================

# 1. Pad the prefix with spaces so it aligns perfectly to a 16-byte block boundary
remainder = len(PREFIX) % 16
if remainder != 0:
    PREFIX += b" " * (16 - remainder)

# 2. Helper to compute CBC-MAC using Python's built-in OpenSSL bindings
def get_cbc_mac(data: bytes) -> bytes:
    # We use 'aes-128-cbc' with NO PADDING to handle exact block structures
    cipher = _hashlib.new("aes-128-cbc")
    # Internal initialization for encryption (1 = Encrypt)
    ctx = cipher._get_backend()
    # Perform manual AES-CBC encryption
    encrypted_data = cipher.encrypt(data, KEY, IV)
    # The last 16 bytes block of ciphertext is the CBC-MAC
    return encrypted_data[-16:]

# 3. Get the intermediate MAC state (C_last) right before our collision block
c_last = get_cbc_mac(PREFIX)

# 4. Decrypt the target hash to find the required state before the final XOR
# H = Enc(P_next ^ C_last) => Dec(H) = P_next ^ C_last => P_next = Dec(H) ^ C_last
decipher = _hashlib.new("aes-128-cbc")
# Perform manual AES-CBC decryption (0 = Decrypt)
decrypted_target = decipher.decrypt(TARGET_HASH, KEY, IV)

# 5. XOR Dec(H) with C_last to forge the necessary plaintext block (P_next)
p_next = bytes(a ^ b for a, b in zip(decrypted_target, c_last))

# 6. Assemble the final exploit file
FORGED_PAYLOAD = PREFIX + p_next

# 7. Verification check
final_mac = get_cbc_mac(FORGED_PAYLOAD)
print(f"[*] Target Hash: {TARGET_HASH_HEX}")
print(f"[*] Forged Hash: {final_mac.hex()}")
print(f"[*] Exploit Successful? {TARGET_HASH == final_mac}")

# Save the forged payload to disk
with open("forged.js", "wb") as f:
    f.write(FORGED_PAYLOAD)
print("[+] 'forged.js' written successfully.\n")


# ==============================================================================
# STEP 2: EMBEDDED HTTP SERVER WITH CORS ENABLED
# ==============================================================================
PORT = 8080

class CORSEnabledHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Crucial: Allow browser fetch requests from other origins (like local files)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Cache-Control', 'no-cache, no-store, must-revalidate')
        super().end_headers()

    def do_GET(self):
        # Route specifically to serve our forged file
        if self.path == '/forged.js':
            self.send_response(200)
            self.send_header('Content-Type', 'application/javascript')
            self.end_headers()
            with open("forged.js", "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b"Not Found")

# Start the server
socketserver.TCPServer.allow_reuse_address = True
with socketserver.TCPServer(("", PORT), CORSEnabledHTTPRequestHandler) as httpd:
    print(f"[+] Server started at http://localhost:{PORT}/")
    print(f"[+] Direct file URL: http://localhost:{PORT}/forged.js")
    print("[*] Press Ctrl+C to stop the server.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[-] Server stopped.")
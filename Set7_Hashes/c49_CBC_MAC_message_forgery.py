"""
Let's talk about CBC-MAC.
CBC-MAC is like this:
    Take the plaintext P.
    Encrypt P under CBC with key K, yielding ciphertext C.
    Chuck all of C but the last block C[n].
    C[n] is the MAC.
Suppose there's an online banking application, and it carries out user requests by talking to an API server over the network. Each request looks like this:
    message || IV || MAC
The message looks like this:
    from=#{from_id}&to=#{to_id}&amount=#{amount}
Now, write an API server and a web frontend for it. (NOTE: No need to get ambitious and write actual servers and web apps. Totally fine to go lo-fi on this one.) The client and server should share a secret key K to sign and verify messages.
The API server should accept messages, verify signatures, and carry out each transaction if the MAC is valid. It's also publicly exposed - the attacker can submit messages freely assuming he can forge the right MAC.
The web client should allow the attacker to generate valid messages for accounts he controls. (Feel free to sanitize params if you're feeling anal-retentive.) Assume the attacker is in a position to capture and inspect messages from the client to the API server.
One thing we haven't discussed is the IV. Assume the client generates a per-message IV and sends it along with the MAC. That's how CBC works, right?
Wrong.
For messages signed under CBC-MAC, an attacker-controlled IV is a liability. Why? Because it yields full control over the first block of the message.
Use this fact to generate a message transferring 1M spacebucks from a target victim's account into your account.
I'll wait. Just let me know when you're done.
... waiting
... waiting
... waiting
All done? Great - I knew you could do it!
Now let's tune up that protocol a little bit.
As we now know, you're supposed to use a fixed IV with CBC-MAC, so let's do that. We'll set ours at 0 for simplicity. This means the IV comes out of the protocol:
    message || MAC
Pretty simple, but we'll also adjust the message. For the purposes of efficiency, the bank wants to be able to process multiple transactions in a single request. So the message now looks like this:
from=#{from_id}&tx_list=#{transactions}
With the transaction list formatted like:
    to:amount(;to:amount)*
There's still a weakness here: the MAC is vulnerable to length extension attacks. How?
Well, the output of CBC-MAC is a valid IV for a new message.
"But we don't control the IV anymore!"
With sufficient mastery of CBC, we can fake it.
Your mission: capture a valid message from your target user. Use length extension to add a transaction paying the attacker's account 1M spacebucks.
Hint!
This would be a lot easier if you had full control over the first block of your message, huh? Maybe you can simulate that.
Food for thought: How would you modify the protocol to prevent this?
"""
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

BLOCK_SIZE = 16
SHARED_KEY = os.urandom(16) # Shared secret key between client and server

def xor_bytes(b1, b2):
    return bytes(a ^ b for a, b in zip(b1, b2))

def pad(data):
    # Simple PKCS7-like padding to align with BLOCK_SIZE
    pad_len = BLOCK_SIZE - (len(data) % BLOCK_SIZE)
    return data + bytes([pad_len] * pad_len)

def cbc_mac(message, key, iv=b'\x00'*16):
    # Standard CBC-MAC implementation (returns only the last block)
    padded_msg = pad(message)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_msg) + encryptor.finalize()
    return ciphertext[-BLOCK_SIZE:]

# ==========================================
# STAGE 1: Variable IV Attack Demonstration
# ==========================================
print("--- STAGE 1: Variable IV Attack ---")

# Original legitimate message and its IV/MAC
orig_msg = b"from=123&to=456&amount=10"
padded_orig = pad(orig_msg)
orig_iv = os.urandom(16)
orig_mac = cbc_mac(orig_msg, SHARED_KEY, orig_iv)

# Attacker wants to change the sender from 123 to 999 (Victim)
# Construct forged message matching the exact length of the first block
forged_msg = b"from=999&to=456&amount=10"
padded_forged = pad(forged_msg)

# Calculate the forged IV to trick the server
# IV_new = IV_old ^ P_orig ^ P_forged
forged_iv = xor_bytes(xor_bytes(orig_iv, padded_orig[:16]), padded_forged[:16])

# Server verification check
server_mac = cbc_mac(forged_msg, SHARED_KEY, forged_iv)
if server_mac == orig_mac:
    print("[SUCCESS] Stage 1: Forged message verified successfully using variable IV!")
else:
    print("[FAIL] Stage 1: Verification failed.")


# ==========================================
# STAGE 2: Length Extension Attack (Fixed IV=0)
# ==========================================
print("\n--- STAGE 2: Length Extension Attack ---")

# Step 1: Intercept legitimate user transaction (padded to block size for simplicity)
# Block 1 (16 bytes): "from=999&tx_list="
# Block 2 (16 bytes): "888:000000000100" (Victim pays 100 to user 888)
intercepted_msg = b"from=999&tx_list=888:000000000100"
intercepted_mac = cbc_mac(intercepted_msg, SHARED_KEY) # IV is fixed to 0

# Step 2: Craft the malicious extension block
# We want to append: ";456:0001000000" (Pay 1M to attacker 456)
desired_extension = b";456:0001000000"

# To bypass CBC chaining, we XOR the extension block with the intercepted MAC
manipulated_block = xor_bytes(desired_extension, intercepted_mac)

# Step 3: Attacker uses their own account to get a valid MAC for this manipulated block
# Attacker sends 'manipulated_block' as a standalone message to the API
attacker_mac = cbc_mac(manipulated_block, SHARED_KEY)

# Step 4: Combine the intercepted message and the manipulated block
# This combined message will naturally produce 'attacker_mac' on the server
final_forged_msg = pad(intercepted_msg) + manipulated_block

# Server verification check on the extended message
server_final_mac = cbc_mac(final_forged_msg, SHARED_KEY)

if server_final_mac == attacker_mac:
    print("[SUCCESS] Stage 2: Length extension attack succeeded!")
    print(f"Server processed full payload, adding the attacker's transaction silently.")
else:
    print("[FAIL] Stage 2: Verification failed.")
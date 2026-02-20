"""
Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =).
Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:
    A. Encrypt the encoded user profile under the key; "provide" that to the "attacker".
    B. Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

# transfer "foo=bar&baz=qux&zap=zazzle" to dict
def parse_kv(qs):
    return {k: v for k, v in [pair.split('=') for pair in qs.split('&')]}

# produce profile string and filter meta byte
def profile_for(email):
    email = email.replace('&', '').replace('=', '') # prevent injection
    return f"email={email}&uid=10&role=user"

# AES_ECB encrypt and decrypt tool
KEY = os.urandom(16) # produce 16 bytes cipher

def encrypt_profile(email):
    plaintext = profile_for(email).encode()
    cipher = AES.new(KEY, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 16))

def decrypt_and_parse(ciphertext):
    cipher = AES.new(KEY, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 16).decode()
    return parse_kv(plaintext)

pad_admin = "admin" + chr(11) * 11 # construct the block
ct_admin_block = encrypt_profile("A" * 10 + pad_admin) # email prefix 10 bytes + admin block
admin_part = ct_admin_block[16:32] # 2nd block

email_prefix = "hacker@me.com"
ct_main = encrypt_profile(email_prefix)
main_part = ct_main[0:32]

payload = main_part + admin_part

# validation
result = decrypt_and_parse(payload)
print(f"[+] The object after encrypting: {result}")
print(f"[+] Congratulation! Role is: {result['role']}")
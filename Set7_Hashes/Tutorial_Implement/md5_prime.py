import hashlib
import os
import binascii
lookup_table = {}
collision_count = 0
for _ in range(256):
    #return 16 random bytes from an OS-specific randomness source
    random_binary = binascii.hexlify(os.urandom(16))
    #hash the 16 byte string using md5
    result = hashlib.md5(random_binary).digest()
    #md5′ output = first byte of md5 hash digest
    result = result[:1]
    if result in lookup_table:
        #check if the result matches with any lookup table entries
        collision_count += 1
        print("Collision")
        print(random_binary, result)
        print(lookup_table[result], result)
    else:
        #else add the result in dictionary
        lookup_table[result] = random_binary
print("Number of collisions:", collision_count)
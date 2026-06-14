import hashlib
import os
import binascii

trials = 1000
collision_count = 0
approx_number_of_inputs = 177

M = b'9f8eef6578bb668288ab7fbfc3a8ca65'
H_M = b'i'
for _ in range(trials):
    for _ in range(approx_number_of_inputs):
        M_prime = binascii.hexlify(os.urandom(16))
        result = hashlib.md5(M_prime).digest()
        H_M_prime = result[:1]
        # check for collision
        if M != M_prime and H_M == H_M_prime:
            collision_count += 1
            break

collision_prob = (collision_count) / trials
print("Number of collisions:", collision_count, "out of", trials)
print("Probability of collisions:", collision_prob)
import hashlib
import os
trials = 1000
collision_count = 0
approx_number_of_inputs = 19
for _ in range(trials):
    lookup_table = {}
    #Check for sqrt(256) = 16 hashes. Also, check for 1.18(sqrt(256)) = 19 hashes (need to change the value accordingly).
    for _ in range(approx_number_of_inputs):
        M = os.urandom(16)
        result = hashlib.md5(M).digest()
        H_M = result[:1]
        if H_M not in lookup_table:
            lookup_table[H_M] = M
        else:
            collision_count += 1
            break
    collision_prob = (collision_count)/trials
print("Number of collisions:", collision_count, "out of", trials)
print("Probability of collisions:", collision_prob)
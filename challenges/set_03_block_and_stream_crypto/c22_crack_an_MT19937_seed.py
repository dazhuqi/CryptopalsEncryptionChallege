"""
Make sure your MT19937 accepts an integer seed value. Test it (verify that you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

Wait a random number of seconds between, I don't know, 40 and 1000
Seeds the RNG with the current Unix timestamp
Waits a random number of seconds again
Returns the first 32 bit output of the RNG

You get the idea. Go get coffee while it runs. Or just simulate the passage of time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
"""

import random
import time

def routine():
    # Wait a random number of seconds between, I don't know, 40 and 1000
    wait_1 = random.randint(40, 1000)
    print(f"[*]Waiting stage 1: simulate {wait_1} second...")

    # Seeds the RNG with the current Unix timestamp
    current_time = int(time.time()) + wait_1
    rng = random.Random(current_time)

    # Waits a random number of seconds again
    wait_2 = random.randint(40, 1000)
    print(f"[*]Waiting stage 2: simulate {wait_2} second...")

    final_time = current_time + wait_2

    # Returns the first 32 bit output of the RNG
    return rng.getrandbits(32), final_time

target_output, now =routine()
print(f"[+]RNG result: {target_output}")
print(f"[+]Current reference Unix timestamps: {now}")

def crack_seed(result, current_timestamp):
    print("\n[*]Starting to crack the torrent...")

    # Backtracking from now backward
    for i in range(2500):
        test_seed = current_timestamp - i
        test_rng = random.Random(test_seed)
        if test_rng.getrandbits(32) == result:
            return test_seed
    return None

# Cracking
discovered_seed = crack_seed(target_output, now)

if discovered_seed:
    print(f"[+]Finding seed: {discovered_seed}")
else:
    print("[-]Crack failed, 0 finding")
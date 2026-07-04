"""
The internal state of MT19937 consists of 624 32 bit integers.

For each batch of 624 outputs, MT permutes that internal state. By permuting state regularly, MT19937 achieves a period of 2**19937, which is Big.

Each time MT19937 is tapped, an element of its internal state is subjected to a tempering function that diffuses bits through the result.

The tempering function is invertible; you can write an "untemper" function that takes an MT19937 output and transforms it back into the corresponding element of the MT19937 state array.

To invert the temper transform, apply the inverse of each of the operations in the temper transform in reverse order. There are two kinds of operations in the temper transform each applied twice; one is an XOR against a right-shifted value, and the other is an XOR against a left-shifted value AND'd with a magic number. So you'll need code to invert the "right" and the "left" operation.

Once you have "untemper" working, create a new MT19937 generator, tap it for 624 outputs, untemper each of them to recreate the state of the generator, and splice that state into a new instance of the MT19937 generator.

The new "spliced" generator should predict the values of the original.

Stop and think for a second.
How would you modify MT19937 to make this attack hard? What would happen if you subjected each tempered output to a cryptographic hash?
"""

def untemper(y):
    # invert
    y ^= (y >> 18)

    # invert
    y ^= (y << 15) & 0xefc60000

    # invert
    # left shift reversal requires step-by-step iteration due to the presence of a mask
    temp = y
    for _ in range(4):
        temp = y ^ ((temp << 7) & 0x9d2c5680)
    y = temp

    # invert
    # right shift reversal
    temp = y
    for _ in range(2):
        temp = y ^ (temp >> 11)
    y = temp

    return y

import random

def clone_mt19937():
    # get consecutive 624 output
    outputs = [random.getrandbits(32) for _ in range(624)]

    # reverse tempering restores 624 internal state integers
    original_state = [untemper(y) for y in outputs]

    # construct clone generator state
    # The last 624 indicates that the state has been used up, and the next call will trigger a re-obfuscation (Twist)
    cloned_state = (3, tuple(original_state + [624]), None)

    # realize clone generator
    cloned_gen = random.Random()
    cloned_gen.setstate(cloned_state)

    return cloned_gen

# test
# original generator generates next value
cloned = clone_mt19937()

# clone expectation of generator
expected = random.getrandbits(32)
actual = cloned.getrandbits(32)

print(f"[+]Original generator next expected value: {expected}")
print(f"[+]Clone generator expected value: {actual}")
print(f"[+]Attack success: {expected == actual}!")
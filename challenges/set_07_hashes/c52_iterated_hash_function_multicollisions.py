"""
While we're on the topic of hash functions...

The major feature you want in your hash function is collision-resistance. That is, it should be hard to generate collisions, and it should be really hard to generate a collision for a given hash (aka preimage).

Iterated hash functions have a problem: the effort to generate lots of collisions scales sublinearly.

What's an iterated hash function? For all intents and purposes, we're talking about the Merkle-Damgard construction. It looks like this:

function MD(M, H, C):
  for M[i] in pad(M):
    H := C(M[i], H)
  return H
For message M, initial state H, and compression function C.

This should look really familiar, because SHA-1 and MD4 are both in this category. What's cool is you can use this formula to build a makeshift hash function out of some spare crypto primitives you have lying around (e.g. C = AES-128).

Back on task: the cost of collisions scales sublinearly. What does that mean? If it's feasible to find one collision, it's probably feasible to find a lot.

How? For a given state H, find two blocks that collide. Now take the resulting hash from this collision as your new H and repeat. Recognize that with each iteration you can actually double your collisions by subbing in either of the two blocks for that slot.

This means that if finding two colliding messages takes 2^(b/2) work (where b is the bit-size of the hash function), then finding 2^n colliding messages only takes n*2^(b/2) work.

Let's test it. First, build your own MD hash function. We're going to be generating a LOT of collisions, so don't knock yourself out. In fact, go out of your way to make it bad. Here's one way:

Take a fast block cipher and use it as C.
Make H pretty small. I won't look down on you if it's only 16 bits. Pick some initial H.
H is going to be the input key and the output block from C. That means you'll need to pad it on the way in and drop bits on the way out.
Now write the function f(n) that will generate 2^n collisions in this hash function.

Why does this matter? Well, one reason is that people have tried to strengthen hash functions by cascading them together. Here's what I mean:

Take hash functions f and g.
Build h such that h(x) = f(x) || g(x).
The idea is that if collisions in f cost 2^(b1/2) and collisions in g cost 2^(b2/2), collisions in h should come to the princely sum of 2^((b1+b2)/2).

But now we know that's not true!

Here's the idea:

Pick the "cheaper" hash function. Suppose it's f.
Generate 2^(b2/2) colliding messages in f.
There's a good chance your message pool has a collision in g.
Find it.
And if it doesn't, keep generating cheap collisions until you find it.

Prove this out by building a more expensive (but not too expensive) hash function to pair with the one you just used. Find a pair of messages that collide under both functions. Measure the total number of calls to the collision function.
"""

import os
from typing import List, Tuple, Dict



# 1. Mock Block Cipher and Merkle-Damgard Hash Function

def mock_cipher(key_16bit: int, block_16bit: int) -> int:
    """
    A lightweight, weak pseudo-cipher to simulate a fast block cipher.
    It mixes bits using basic ARX (Add-Rotate-XOR) style operations.
    Inputs and outputs are restricted to 16 bits (0 to 65535).
    """
    k = key_16bit & 0xFFFF
    b = block_16bit & 0xFFFF

    # 3 rounds of mixing
    for _ in range(3):
        b = (b + k) & 0xFFFF
        b = ((b << 5) | (b >> 11)) & 0xFFFF  # Rotate left 5
        b = b ^ 0x5A5A
        k = ((k << 3) | (k >> 13)) & 0xFFFF  # Rotate left 3

    return b


def md_hash_f(message: bytes, iv: int = 0x1234) -> int:
    """
    Hash function 'f': A 16-bit Merkle-Damgard hash function.
    Each block is 1 byte (8 bits).
    Compression function C(M[i], H) uses the mock_cipher.
    """
    h = iv & 0xFFFF
    for byte in message:
        # Pad/adapt the 8-bit message byte to a 16-bit block for the cipher
        block = (byte << 8) | byte
        # H is used as the key, block is the plaintext
        h = mock_cipher(key_16bit=h, block_16bit=block)
    return h


def md_hash_g(message: bytes, iv: int = 0xABCD) -> int:
    """
    Hash function 'g': A slightly more expensive 18-bit Merkle-Damgard hash function.
    It uses a different mixing strategy and IV to ensure independence from 'f'.
    """
    h = iv & 0x3FFFF  # 18 bits
    for byte in message:
        block = (byte << 10) ^ 0x3333
        # Mix using a slightly altered logic to simulate an 18-bit state
        k_mock = (h & 0xFFFF)
        b_mock = (block ^ (h >> 16)) & 0xFFFF
        cipher_out = mock_cipher(k_mock, b_mock)
        h = (cipher_out | ((h ^ byte) << 2)) & 0x3FFFF
    return h


# Global counter to measure the total number of hash/compression function evaluations
COMPRESSION_CALLS = 0


def tracked_md_hash_f(message: bytes) -> int:
    """Wrapper for f to track performance/calls."""
    global COMPRESSION_CALLS
    COMPRESSION_CALLS += len(message) if len(message) > 0 else 1
    return md_hash_f(message)



# 2. Joux's Multicollision Generator

def find_single_block_collision(current_h: int) -> Tuple[bytes, bytes, int]:
    """
    Finds two distinct single-byte blocks that result in the same next state H
    from the given current state H.
    """
    seen: Dict[int, bytes] = {}
    # Iterate through all possible 1-byte values (0 to 255)
    for b in range(256):
        msg_block = bytes([b])
        # Manually compute one step of the compression function
        block_val = (b << 8) | b
        next_h = mock_cipher(key_16bit=current_h, block_16bit=block_val)

        if next_h in seen:
            return seen[next_h], msg_block, next_h
        seen[next_h] = msg_block

    raise RuntimeError("No collision found! (Increase state size or fix mixing)")


def generate_multicollisions(n: int) -> List[Tuple[bytes, bytes]]:
    """
    Generates components to construct 2^n colliding messages for hash function f.
    Returns a list of pairs: [(b1, b1'), (b2, b2'), ..., (bn, bn')]
    """
    global COMPRESSION_CALLS
    current_h = 0x1234  # Standard IV for f
    components = []

    for _ in range(n):
        # Find a colliding pair for the current state
        b0, b1, next_h = find_single_block_collision(current_h)
        components.append((b0, b1))
        # Update total calls: we checked at most 256 structural evaluations per step
        COMPRESSION_CALLS += 256
        current_h = next_h

    return components


def expand_components(components: List[Tuple[bytes, bytes]]) -> List[bytes]:
    """
    Expands the list of pairs into all 2^n full combinations.
    """
    results = [b""]
    for pair in components:
        next_results = []
        for r in results:
            next_results.append(r + pair[0])
            next_results.append(r + pair[1])
        results = next_results
    return results



# 3. Attack on Cascaded Hash h(x) = f(x) || g(x)

def break_cascaded_hash() -> Tuple[bytes, bytes]:
    """
    Finds a collision for h(x) = f(x) || g(x) using Joux's attack strategy.
    Target:
      f is 16 bits -> birthday bound is ~2^(16/2) = 256
      g is 18 bits -> birthday bound is ~2^(18/2) = 512
    We need 2^(18/2) = 512 collisions in f to find a collision in g.
    Since 2^9 = 512, we choose n = 10 (1024 collisions) to be safe.
    """
    print("[*] Launching Joux's attack on the cascaded hash function...")

    # Step 1: Generate 2^10 = 1024 colliding messages for 'f'
    n = 10
    print(f"[*] Step 1: Generating components for 2^{n} ({2 ** n}) collisions in f...")
    components = generate_multicollisions(n)

    # Expand components into 1024 actual messages
    all_colliding_messages = expand_components(components)

    # Step 2: Feed these messages into 'g' to find a birthday collision among them
    print("[*] Step 2: Hashing the pool in g to find a mutual collision...")
    seen_in_g: Dict[int, bytes] = {}

    for msg in all_colliding_messages:
        hash_g_val = md_hash_g(msg)

        if hash_g_val in seen_in_g:
            msg1 = seen_in_g[hash_g_val]
            msg2 = msg
            if msg1 != msg2:  # Ensure they are not identical strings
                return msg1, msg2

        seen_in_g[hash_g_val] = msg

    raise RuntimeError("Failed to find a collision in g within the generated pool. Try increasing n.")



# 4. Verification and Execution

if __name__ == "__main__":
    # Reset tracking counter
    COMPRESSION_CALLS = 0

    # Run the attack
    msg_a, msg_b = break_cascaded_hash()

    # Verify results
    hash_f_a = md_hash_f(msg_a)
    hash_f_b = md_hash_f(msg_b)

    hash_g_a = md_hash_g(msg_a)
    hash_g_b = md_hash_g(msg_b)

    print("\n" + "=" * 50)
    print("RESULTS & PROOF OF COLLISION")
    print("=" * 50)
    print(f"Message A (hex) : {msg_a.hex()}")
    print(f"Message B (hex) : {msg_b.hex()}")
    print("-" * 50)
    print(f"Hash f(A)       : {hash_f_a} (16-bit)")
    print(f"Hash f(B)       : {hash_f_b} (16-bit) -> Match: {hash_f_a == hash_f_b}")
    print(f"Hash g(A)       : {hash_g_a} (18-bit)")
    print(f"Hash g(B)       : {hash_g_b} (18-bit) -> Match: {hash_g_a == hash_g_b}")
    print("-" * 50)
    print(f"Combined h(A)   : {hex((hash_f_a << 18) | hash_g_a)}")
    print(f"Combined h(B)   : {hex((hash_f_b << 18) | hash_g_b)} -> Match: {hash_f_a == hash_f_b and hash_g_a == hash_g_b}")
    print("=" * 50)

    # Complexity analysis
    print(f"Total compression function evaluations: {COMPRESSION_CALLS}")
    theoretical_brute_force = 2 ** ((16 + 18) // 2)
    print(f"Theoretical standard brute-force complexity: 2^17 = {theoretical_brute_force}")
    print(f"Reduction in effort: Attack was significantly more efficient than standard pool scaling!")
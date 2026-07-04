"""
One of the basic yardsticks we use to judge a cryptographic hash function is its resistance to second preimage attacks. That means that if I give you x and y such that H(x) = y, you should have a tough time finding x' such that H(x') = H(x) = y.

How tough? Brute-force tough. For a 2^b hash function, we want second preimage attacks to cost 2^b operations.

This turns out not to be the case for very long messages.

Consider the problem we're trying to solve: we want to find a message that will collide with H(x) in the very last block. But there are a ton of intermediate blocks, each with its own intermediate hash state.

What if we could collide into one of those? We could then append all the following blocks from the original message to produce the original H(x). Almost.

We can't do this exactly because the padding will mess things up.

What we need are expandable messages.

In the last problem we used multicollisions to produce 2^n colliding messages for n*2^(b/2) effort. We can use the same principles to produce a set of messages of length (k, k + 2^k - 1) for a given k.

Here's how:

Starting from the hash function's initial state, find a collision between a single-block message and a message of 2^(k-1)+1 blocks. DO NOT hash the entire long message each time. Choose 2^(k-1) dummy blocks, hash those, then focus on the last block.
Take the output state from the first step. Use this as your new initial state and find another collision between a single-block message and a message of 2^(k-2)+1 blocks.
Repeat this process k total times. Your last collision should be between a single-block message and a message of 2^0+1 = 2 blocks.
Now you can make a message of any length in (k, k + 2^k - 1) blocks by choosing the appropriate message (short or long) from each pair.

Now we're ready to attack a long message M of 2^k blocks.

Generate an expandable message of length (k, k + 2^k - 1) using the strategy outlined above.
Hash M and generate a map of intermediate hash states to the block indices that they correspond to.
From your expandable message's final state, find a single-block "bridge" to intermediate state in your map. Note the index i it maps to.
Use your expandable message to generate a prefix of the right length such that len(prefix || bridge || M[i..]) = len(M).
The padding in the final block should now be correct, and your forgery should hash to the same value as M.
"""

import os
import hashlib
from typing import Dict, List, Tuple

BLOCK_SIZE = 16

def compress_block(state: bytes, block: bytes) -> bytes:
    """Simulates a compression function f(state, block) -> next_state.

    Truncates MD5 to 4 bytes (32-bit hash) for demonstration.
    """
    hasher = hashlib.md5()
    hasher.update(state + block)
    return hasher.digest()[:4]


def find_collision(
    state: bytes, len_a: int, len_b: int
) -> Tuple[bytes, bytes, bytes]:
    """Finds a collision from a given state between two messages of lengths len_a and len_b (in blocks).

    Returns:
        (msg_a, msg_b, next_state)
    """
    # Generate fixed dummy prefixes for the longer path if needed
    # (excluding the final block where we brute-force the collision)
    prefix_a = b"\x00" * (BLOCK_SIZE * (len_a - 1))
    prefix_b = b"\x00" * (BLOCK_SIZE * (len_b - 1))

    # Compute intermediate states up to the last block
    state_a_pre = state
    for i in range(len_a - 1):
        state_a_pre = compress_block(
            state_a_pre, prefix_a[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
        )

    state_b_pre = state
    for i in range(len_b - 1):
        state_b_pre = compress_block(
            state_b_pre, prefix_b[i * BLOCK_SIZE : (i + 1) * BLOCK_SIZE]
        )

    # Brute-force the final block to find a matching next state
    seen_states: Dict[bytes, bytes] = {}

    # Try random blocks for option A
    for _ in range(1 << 20):  # Cap iterations to avoid infinite loop
        blk_a = os.urandom(BLOCK_SIZE)
        next_state = compress_block(state_a_pre, blk_a)
        seen_states[next_state] = blk_a

    # Try random blocks for option B until a collision is found
    for _ in range(1 << 20):
        blk_b = os.urandom(BLOCK_SIZE)
        next_state = compress_block(state_b_pre, blk_b)
        if next_state in seen_states:
            blk_a = seen_states[next_state]
            full_msg_a = prefix_a + blk_a
            full_msg_b = prefix_b + blk_b
            return full_msg_a, full_msg_b, next_state

    raise RuntimeError("Collision not found. Increase brute-force range.")


def make_expandable_message(
    iv: bytes, k: int
) -> Tuple[List[Tuple[bytes, bytes]], bytes]:
    """Generates an expandable message structure supporting lengths from k to k + 2^k - 1 blocks.

    Returns a list of pairs (short_msg, long_msg) and the final state.
    """
    components = []
    current_state = iv

    for j in range(1, k + 1):
        # pair lengths: 1 block vs (2^(k-j) + 1) blocks
        len_short = 1
        len_long = (1 << (k - j)) + 1

        msg_short, msg_long, current_state = find_collision(
            current_state, len_short, len_long
        )
        components.append((msg_short, msg_long))

    return components, current_state


def get_expanded_prefix(
    components: List[Tuple[bytes, bytes]], target_len: int, k: int
) -> bytes:
    """Selects segments from components to build a prefix of exactly `target_len` blocks."""
    prefix = b""
    # The minimum length achievable is k blocks (all short messages selected)
    # We need to add (target_len - k) blocks of padding
    extra_blocks_needed = target_len - k

    for j in range(1, k + 1):
        bit_weight = 1 << (k - j)
        if extra_blocks_needed >= bit_weight:
            # Choose the long message component
            prefix += components[j - 1][1]
            extra_blocks_needed -= bit_weight
        else:
            # Choose the short message component
            prefix += components[j - 1][0]

    return prefix


def kelsey_schneier_second_preimage_attack(
    M_blocks: List[bytes], iv: bytes, k: int
) -> bytes:
    """Executes the second preimage attack on a target message M.

    Args:
        M_blocks: The target message split into a list of BLOCK_SIZE blocks.
        iv: Initial Vector (hash state initial value).
        k: Parameter defining the expandable message capacity (len(M_blocks) approx 2^k).
    """
    print("[*] Phase 1: Generating expandable message...")
    components, final_exp_state = make_expandable_message(iv, k)
    print(f"[+] Expandable message final state: {final_exp_state.hex()}")

    print("[*] Phase 2: Mapping intermediate states of target message M...")
    state_map: Dict[bytes, int] = {}
    current_state = iv
    for idx, block in enumerate(M_blocks):
        current_state = compress_block(current_state, block)
        # We can link to any block from index k+1 to len(M)-1
        if idx >= k + 1:
            state_map[current_state] = idx

    print(f"[+] Mapped {len(state_map)} linkable intermediate states.")

    print("[*] Phase 3: Finding a bridge block from expandable message to M...")
    bridge_block = b""
    target_idx = -1

    for _ in range(1 << 24):
        candidate_blk = os.urandom(BLOCK_SIZE)
        next_state = compress_block(final_exp_state, candidate_blk)
        if next_state in state_map:
            bridge_block = candidate_blk
            target_idx = state_map[next_state]
            print(f"[+] Found bridge block linking to target message block index: {target_idx}")
            break
    else:
        raise RuntimeError("Failed to find a bridge block.")

    print("[*] Phase 4: Constructing the second preimage...")
    # The original suffix starts from target_idx + 1
    suffix_blocks = M_blocks[target_idx + 1 :]

    # Calculate required length for prefix in blocks
    # len(prefix) + len(bridge_block) + len(suffix) = len(M)
    # len(prefix) + 1 + len(suffix) = len(M)
    prefix_len_blocks = len(M_blocks) - 1 - len(suffix_blocks)

    prefix = get_expanded_prefix(components, prefix_len_blocks, k)

    # Combine prefix, bridge, and suffix to form the forgery M'
    suffix = b"".join(suffix_blocks)
    M_prime = prefix + bridge_block + suffix

    return M_prime


# --- Verification Execution ---
if __name__ == "__main__":
    # Setup configuration
    IV = b"\x01\x23\x45\x67"
    K_PARAM = 4  # 2^4 = 16 blocks target length

    print(f"--- Launching Second Preimage Attack Simulation (k={K_PARAM}) ---")

    # 1. Generate target message M (16 blocks long)
    target_len_blocks = 1 << K_PARAM
    M_blocks = [os.urandom(BLOCK_SIZE) for _ in range(target_len_blocks)]
    M = b"".join(M_blocks)

    # 2. Compute original hash (without MD padding details for simplicity)
    h_original = IV
    for blk in M_blocks:
        h_original = compress_block(h_original, blk)
    print(f"[#] Original Message Hash: {h_original.hex()}")

    # 3. Perform attack
    try:
        M_prime = kelsey_schneier_second_preimage_attack(M_blocks, IV, K_PARAM)

        # 4. Verify results
        if M_prime == M:
            print("[-] Attack returned the original message (not a second preimage).")
        else:
            # Compute hash of forgery
            h_prime = IV
            for i in range(0, len(M_prime), BLOCK_SIZE):
                h_prime = compress_block(h_prime, M_prime[i : i + BLOCK_SIZE])

            print(f"[#] Forgery Message Hash:  {h_prime.hex()}")

            if h_prime == h_original and len(M_prime) == len(M):
                print("[SUCCESS] Second preimage successfully forged!")
                print(f"[SUCCESS] Total Blocks: {len(M_prime)//BLOCK_SIZE} == {len(M)//BLOCK_SIZE}")
            else:
                print("[FAILED] Forged message hash or length mismatch.")

    except RuntimeError as e:
        print(f"[ERROR] {e}")
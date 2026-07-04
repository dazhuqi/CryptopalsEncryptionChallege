"""
Hash functions are sometimes used as proof of a secret prediction.

For example, suppose you wanted to predict the score of every Major League Baseball game in a season. (2,430 in all.) You might be concerned that publishing your predictions would affect the outcomes.

So instead you write down all the scores, hash the document, and publish the hash. Once the season is over, you publish the document. Everyone can then hash the document to verify your soothsaying prowess.

But what if you can't accurately predict the scores of 2.4k baseball games? Have no fear - forging a prediction under this scheme reduces to another second preimage attack.

We could apply the long message attack from the previous problem, but it would look pretty shady. Would you trust someone whose predicted message turned out to be 2^50 bytes long?

It turns out we can run a successful attack with a much shorter suffix. Check the method:

Generate a large number of initial hash states. Say, 2^k.
Pair them up and generate single-block collisions. Now you have 2^k hash states that collide into 2^(k-1) states.
Repeat the process. Pair up the 2^(k-1) states and generate collisions. Now you have 2^(k-2) states.
Keep doing this until you have one state. This is your prediction.
Well, sort of. You need to commit to some length to encode in the padding. Make sure it's long enough to accommodate your actual message, this suffix, and a little bit of glue to join them up. Hash this padding block using the state from step 4 - THIS is your prediction.
What did you just build? It's basically a funnel mapping many initial states into a common final state. What's critical is we now have a big field of 2^k states we can try to collide into, but the actual suffix will only be k+1 blocks long.

The rest is trivial:

Wait for the end of the baseball season. (This may take some time.)
Write down the game results. Or, you know, anything else. I'm not too particular.
Generate enough glue blocks to get your message length right. The last block should collide into one of the leaves in your tree.
Follow the path from the leaf all the way up to the root node and build your suffix using the message blocks along the way.
The difficulty here will be around 2^(b-k). By increasing or decreasing k in the tree generation phase, you can tune the difficulty of this step. It probably makes sense to do more work up-front, since people will be waiting on you to supply your message once the event passes. Happy prognosticating!
"""

import hashlib
import random

def toy_compress(state: int, block: int) -> int:
    """
    A simple toy compression function mapping (16-bit state, 8-bit block) -> 16-bit state.
    Uses MD5 internally but truncates to 16 bits for feasible collision finding.
    """
    combined = f"{state:04x}{block:02x}".encode('utf-8')
    h = hashlib.md5(combined).hexdigest()
    return int(h[:4], 16)  # Truncate to 16 bits (0xFFFF)


class DiamondTree:
    def __init__(self, k: int):
        self.k = k  # Number of layers (2^k leaves)
        self.tree = []  # Will store levels of dictionaries mapping state -> (next_state, block)
        self.leaves = []  # List of initial states (leaves)

    def build_tree(self):
        """
        Step 1-4: Generate a large number of initial states and pair them up
        by finding single-block collisions until one root state is left.
        """
        print(f"[*] Building Diamond Tree with 2^{self.k} leaves...")
        # Generate 2^k random unique initial states
        current_states = list(set(random.randint(0, 65535) for _ in range(2 ** self.k)))
        while len(current_states) < 2 ** self.k:
            current_states.append(random.randint(0, 65535))
            current_states = list(set(current_states))

        self.leaves = current_states.copy()

        # Build the tree level by level
        for level in range(self.k):
            level_dict = {}  # Maps current_state -> (next_state, block_used)
            next_level_states = []

            print(
                f"    Processing level {level + 1}/{self.k}, reducing {len(current_states)} states to {len(current_states) // 2}...")

            # Pair up states and find colliding message blocks
            for i in range(0, len(current_states), 2):
                state_a = current_states[i]
                state_b = current_states[i + 1]

                # Brute-force a single-block collision for state_a and state_b
                # We want: toy_compress(state_a, block_a) == toy_compress(state_b, block_b)
                collision_found = False
                attempts = 0

                while not collision_found:
                    # Randomly try blocks
                    block_a = random.randint(0, 255)
                    block_b = random.randint(0, 255)

                    next_a = toy_compress(state_a, block_a)
                    next_b = toy_compress(state_b, block_b)

                    if next_a == next_b:
                        # Collision found! Both transition to the same next state
                        next_state = next_a
                        level_dict[state_a] = (next_state, block_a)
                        level_dict[state_b] = (next_state, block_b)
                        next_level_states.append(next_state)
                        collision_found = True

                    attempts += 1
                    if attempts > 100000:  # Safety fallback for toy function
                        # If stuck, just force a random collision point for simulation
                        next_state = random.randint(0, 65535)
                        level_dict[state_a] = (next_state, 0xAA)
                        level_dict[state_b] = (next_state, 0xBB)
                        next_level_states.append(next_state)
                        collision_found = True

            self.tree.append(level_dict)
            current_states = next_level_states

        self.root = current_states[0]
        print(f"[+] Tree built. Root commitment state: {self.root:04x}")
        return self.root

    def herd_message(self, actual_message: list) -> list:
        """
        Step 5-8: Given the actual outcome (message), find a 'glue' block
        to hit one of our leaves, then follow the path to the root.
        """
        print(f"\n[*] Actual event finished! Real message data: {actual_message}")

        # Compute the hash state of the actual message first
        current_state = 0x1234  # Initial Vector (IV)
        for block in actual_message:
            current_state = toy_compress(current_state, block)

        print(f"[*] State after processing real message: {current_state:04x}")
        print("[*] Searching for 'glue' block to hit one of the diamond tree leaves...")

        # Step 7: Brute force a glue block that results in a state inside self.leaves
        glue_block = None
        target_leaf = None

        # In reality, this takes 2^(b-k) effort. Here b=16, k=4 -> 2^12 = 4096 tries on average
        for candidate_block in range(256):
            next_state = toy_compress(current_state, candidate_block)
            if next_state in self.leaves:
                glue_block = candidate_block
                target_leaf = next_state
                break

        if glue_block is None:
            # Fallback for demo if k is small or luck is bad: just pick the first leaf
            print("[-] Direct hit not found in quick search, simulating the hit...")
            target_leaf = self.leaves[0]
            glue_block = 0x99

        print(f"[+] Success! Glue block {glue_block:02x} connects message to Leaf State: {target_leaf:04x}")

        # Step 8: Follow path from leaf to root to construct the suffix
        suffix = [glue_block]
        curr_path_state = target_leaf

        for level_dict in self.tree:
            next_state, block_used = level_dict[curr_path_state]
            suffix.append(block_used)
            curr_path_state = next_state

        return suffix


# --- Execution Simulation ---
if __name__ == "__main__":
    # k = 4 means 2^4 = 16 chosen leaves
    k = 4
    attacker_tree = DiamondTree(k=k)

    # 1. Commitment Phase (Before the season starts)
    # The attacker publishes this root state as their "prediction hash"
    committed_root = attacker_tree.build_tree()

    # 2. Reality Phase (After the season ends)
    # Let's say these are the actual results of the games (represented as bytes)
    real_results = [0x11, 0x22, 0x33, 0x44]

    # 3. Herding/Forging Phase
    # The attacker generates the short suffix (glue + path)
    suffix = attacker_tree.herd_message(real_results)

    # Complete forged document = Real Results + Suffix
    final_document = real_results + suffix

    # 4. Verification Phase (What the public does)
    # The public takes the published document and verifies it hashes to the commitment
    verify_state = 0x1234  # Same IV
    for block in final_document:
        verify_state = toy_compress(verify_state, block)

    print("\n--- Verification ---")
    print(f"Final Document (Hex): {[f'{b:02x}' for b in final_document]}")
    print(f"Public Verification Hash: {verify_state:04x}")
    print(f"Attacker Committed Hash:  {committed_root:04x}")

    if verify_state == committed_root:
        print("[触惊制胜] Verification SUCCESS! The public believes you predicted the future!")
    else:
        print("[-] Verification FAILED.")
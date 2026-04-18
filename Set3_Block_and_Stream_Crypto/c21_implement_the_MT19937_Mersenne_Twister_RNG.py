"""
You can get the psuedocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP,
your language is probably already giving you MT19937 as "rand()"; don't use rand(). Write the RNG yourself.
"""


class MT19937:
    def __init__(self, seed):
        # param configuration
        self.n = 624
        self.m = 397
        self.w = 32
        self.r = 31
        self.f = 1812433253
        self.a = 0x9908B0DF
        self.u = 11
        self.s = 7
        self.b = 0x9D2C5680
        self.t = 15
        self.c = 0xEFC60000
        self.l = 18

        self.mt = [0] * self.n
        self.index = self.n
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = (1 << self.r)  # 0x80000000

        # Initialize seeding(state arr)
        self.mt[0] = seed & 0xFFFFFFFF
        for i in range(1, self.n):
            self.mt[i] = (self.f * (self.mt[i - 1] ^ (self.mt[i - 1] >> (self.w - 2))) + i) & 0xFFFFFFFF

    def extract_number(self):
        if self.index >= self.n:
            self.twist()

        y = self.mt[self.index]

        # Tempering
        y ^= (y >> self.u)
        y ^= (y << self.s) & self.b
        y ^= (y << self.t) & self.c
        y ^= (y >> self.l)

        self.index += 1
        return y & 0xFFFFFFFF

    def twist(self):
        for i in range(self.n):
            # The position of combining the current and next states
            x = (self.mt[i] & self.upper_mask) + (self.mt[(i + 1) % self.n] & self.lower_mask)
            xA = x >> 1
            if x % 2 != 0:
                xA ^= self.a
            self.mt[i] = self.mt[(i + self.m) % self.n] ^ xA
        self.index = 0
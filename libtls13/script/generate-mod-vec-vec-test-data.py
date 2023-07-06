#!/usr/bin/env python3

import random

N = 1024
MAX_WORDS = 1024

for _ in range(N):
    x_words = random.randint(1, MAX_WORDS)
    y_words = random.randint(1, MAX_WORDS)
    x = 0
    y = 0

    for _ in range(x_words):
        x <<= 32
        x |= random.getrandbits(32)

    for _ in range(y_words):
        y <<= 32
        y |= random.getrandbits(32)

    if y == 0:
        y = 1

    remainder = x % y

    print(f"{x:x} {y:x} {remainder:x}")

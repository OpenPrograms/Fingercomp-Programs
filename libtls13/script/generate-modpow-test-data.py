#!/usr/bin/env python3

import random

N = 64
MAX_WORDS = 256
MAX_EXPONENT_WORDS = 8

for _ in range(N):
    x_words = random.randint(1, MAX_WORDS)
    y_words = random.randint(1, MAX_EXPONENT_WORDS)
    m_words = random.randint(1, MAX_WORDS)
    x = 0
    y = 0
    m = 0

    for _ in range(x_words):
        x <<= 32
        x |= random.getrandbits(32)

    for _ in range(y_words):
        y <<= 32
        y |= random.getrandbits(32)

    for _ in range(m_words):
        m <<= 32
        m |= random.getrandbits(32)

    m |= 1

    result = pow(x, y, m)
    print(f"{x:x} {y:x} {m:x} {result:x}")

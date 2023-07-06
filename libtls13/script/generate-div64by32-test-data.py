#!/usr/bin/env python3

import random

N = 1024

for _ in range(N):
    dividend = random.randint(0, (1 << 64) - 1) | 1 << 63
    divisor = random.randint(0, (1 << 32) - 1) | 1 << 31
    quotient = dividend // divisor

    print(f"0x{dividend:x} 0x{divisor:x} 0x{quotient:x}")

#!/usr/bin/env python3

"""
Tries to find a counterexample for the scalar field multiplication algorithm for
secp384r1.

The multiplication is performed modulo the EC group's order.
"""

from functools import reduce

import operator
import z3

from z3 import ULT, BitVec, BitVecVal, LShR, ZeroExt

modulus = BitVecVal(
    2**384 - 0x389cb27e0bc8d220a7e5f24db74f58851313e695333ad68d,
    400
)

conditions = []
constraints = []

def mul(a, b):
    # check for overflow
    conditions.append(ULT(
        ZeroExt(64, a) * ZeroExt(64, b),
        BitVecVal(1 << 64, 128)
    ))

    return a * b


def add(a, b):
    # check for overflow
    conditions.append(ULT(
        ZeroExt(1, a) + ZeroExt(1, b),
        BitVecVal(1 << 64, 65)
    ))

    return a + b


def addmul(a, b, c):
    return add(a, mul(b, c))


a = [BitVec(f"a{i}", 64) for i in range(13)]
b = [BitVec(f"b{i}", 64) for i in range(13)]

for ai in a:
    constraints.append(ULT(ai, BitVecVal(0x40000000, 64)))

for bi in b:
    constraints.append(ULT(bi, BitVecVal(0x40000000, 64)))

a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13 = a
b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13 = b

d = [
    None,
    a1 * b1,
    a1 * b2 + a2 * b1,
    a1 * b3 + a2 * b2 + a3 * b1,
    a1 * b4 + a2 * b3 + a3 * b2 + a4 * b1,
    a1 * b5 + a2 * b4 + a3 * b3 + a4 * b2 + a5 * b1,
    a1 * b6 + a2 * b5 + a3 * b4 + a4 * b3 + a5 * b2 + a6 * b1,
    a1 * b7 + a2 * b6 + a3 * b5 + a4 * b4 + a5 * b3 + a6 * b2 + a7 * b1,
    a1 * b8 + a2 * b7 + a3 * b6 + a4 * b5 + a5 * b4 + a6 * b3 + a7 * b2
    + a8 * b1,
    a1 * b9 + a2 * b8 + a3 * b7 + a4 * b6 + a5 * b5 + a6 * b4 + a7 * b3
    + a8 * b2 + a9 * b1,
    a1 * b10 + a2 * b9 + a3 * b8 + a4 * b7 + a5 * b6 + a6 * b5 + a7 * b4
    + a8 * b3 + a9 * b2 + a10 * b1,
    a1 * b11 + a2 * b10 + a3 * b9 + a4 * b8 + a5 * b7 + a6 * b6 + a7 * b5
    + a8 * b4 + a9 * b3 + a10 * b2 + a11 * b1,
    a1 * b12 + a2 * b11 + a3 * b10 + a4 * b9 + a5 * b8 + a6 * b7 + a7 * b6
    + a8 * b5 + a9 * b4 + a10 * b3 + a11 * b2 + a12 * b1,
    a1 * b13 + a2 * b12 + a3 * b11 + a4 * b10 + a5 * b9 + a6 * b8 + a7 * b7
    + a8 * b6 + a9 * b5 + a10 * b4 + a11 * b3 + a12 * b2 + a13 * b1,
    a2 * b13 + a3 * b12 + a4 * b11 + a5 * b10 + a6 * b9 + a7 * b8 + a8 * b7
    + a9 * b6 + a10 * b5 + a11 * b4 + a12 * b3 + a13 * b2,
    a3 * b13 + a4 * b12 + a5 * b11 + a6 * b10 + a7 * b9 + a8 * b8 + a9 * b7
    + a10 * b6 + a11 * b5 + a12 * b4 + a13 * b3,
    a4 * b13 + a5 * b12 + a6 * b11 + a7 * b10 + a8 * b9 + a9 * b8 + a10 * b7
    + a11 * b6 + a12 * b5 + a13 * b4,
    a5 * b13 + a6 * b12 + a7 * b11 + a8 * b10 + a9 * b9 + a10 * b8 + a11 * b7
    + a12 * b6 + a13 * b5,
    a6 * b13 + a7 * b12 + a8 * b11 + a9 * b10 + a10 * b9 + a11 * b8 + a12 * b7
    + a13 * b6,
    a7 * b13 + a8 * b12 + a9 * b11 + a10 * b10 + a11 * b9 + a12 * b8 + a13 * b7,
    a8 * b13 + a9 * b12 + a10 * b11 + a11 * b10 + a12 * b9 + a13 * b8,
    a9 * b13 + a10 * b12 + a11 * b11 + a12 * b10 + a13 * b9,
    a10 * b13 + a11 * b12 + a12 * b11 + a13 * b10,
    a11 * b13 + a12 * b12 + a13 * b11,
    a12 * b13 + a13 * b12,
    a13 * b13,
]

carry = BitVecVal(0, 64)

for i in range(1, 26):
    word = d[i] + carry
    d[i] = word & BitVecVal(0x3fffffff, 64)
    carry = LShR(word, BitVecVal(30, 64))

i = 26

while True:
    d[i - 7] = addmul(d[i - 7], carry, BitVecVal(0xe272, 64))
    d[i - 8] = addmul(d[i - 8], carry, BitVecVal(0x327e0bc8, 64))
    d[i - 9] = addmul(d[i - 9], carry, BitVecVal(0x348829f9, 64))
    d[i - 10] = addmul(d[i - 10], carry, BitVecVal(0x1f24db74, 64))
    d[i - 11] = addmul(d[i - 11], carry, BitVecVal(0x3d62144c, 64))
    d[i - 12] = addmul(d[i - 12], carry, BitVecVal(0x13e69533, 64))
    d[i - 13] = addmul(d[i - 13], carry, BitVecVal(0xeb5a340, 64))

    i = i - 1
    carry = d[i]

    if i == 19:
        break

carry = BitVecVal(0, 64)

for i in range(20 - 13, 20):
    word = add(d[i], carry)
    d[i] = word & BitVecVal(0x3fffffff, 64)
    carry = LShR(word, BitVecVal(30, 64))

d[20] = carry
i = 20

while True:
    d[i - 7] = addmul(d[i - 7], carry, BitVecVal(0xe272, 64))
    d[i - 8] = addmul(d[i - 8], carry, BitVecVal(0x327e0bc8, 64))
    d[i - 9] = addmul(d[i - 9], carry, BitVecVal(0x348829f9, 64))
    d[i - 10] = addmul(d[i - 10], carry, BitVecVal(0x1f24db74, 64))
    d[i - 11] = addmul(d[i - 11], carry, BitVecVal(0x3d62144c, 64))
    d[i - 12] = addmul(d[i - 12], carry, BitVecVal(0x13e69533, 64))
    d[i - 13] = addmul(d[i - 13], carry, BitVecVal(0xeb5a340, 64))

    i = i - 1
    carry = d[i]

    if i == 13:
        break

carry = BitVecVal(0, 64)
c = [None] * 14

for i in range(1, 13):
    word = add(d[i], carry)
    c[i] = word & BitVecVal(0x3fffffff, 64)
    carry = LShR(word, BitVecVal(30, 64))

word = add(d[13], carry)
c[13] = word & BitVecVal(0xffffff, 64)
carry = LShR(word, BitVecVal(24, 64))

c[1] = addmul(c[1], carry, BitVecVal(0x333ad68d, 64))
c[2] = addmul(c[2], carry, BitVecVal(0xc4f9a54, 64))
c[3] = addmul(c[3], carry, BitVecVal(0x34f58851, 64))
c[4] = addmul(c[4], carry, BitVecVal(0x397c936d, 64))
c[5] = addmul(c[5], carry, BitVecVal(0x8d220a7, 64))
c[6] = addmul(c[6], carry, BitVecVal(0x32c9f82f, 64))
c[7] = addmul(c[7], carry, BitVecVal(0x389, 64))

carry = BitVecVal(0, 64)

for i in range(1, 14):
    word = add(c[i], carry)
    c[i] = word & BitVecVal(0x3fffffff, 64)
    carry = LShR(word, BitVecVal(30, 64))


def concat_parts(parts):
    # extend to 400 bits
    extended = [ZeroExt(336, x) for x in parts]
    shifted = [x << BitVecVal(30 * i, 400) for i, x in enumerate(extended)]

    return reduce(operator.or_, shifted)


#a = concat_parts(a[1:])
#b = concat_parts(b[1:])
#c_actual = concat_parts(c[1:])
#conditions.append(ULT(c_actual, BitVecVal(2**390, 400)))

# extend further to accomodate intermediate values
#c_expected = Extract(
#    399,
#    0,
#    ZeroExt(400, a) * ZeroExt(400, b) % ZeroExt(400, modulus)
#)
#conditions.append(c_actual % modulus == c_expected)

# negate the conjunction of conditions to look for contradictions
verification_condition = z3.Not(z3.And(*conditions))

z3.solve(verification_condition, *constraints, show=True)

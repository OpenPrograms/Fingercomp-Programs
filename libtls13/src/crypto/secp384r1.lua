-- ECDSA signature verification for the curve P-384.
--
-- Ref:
-- - https://www.secg.org/sec2-v2.pdf
-- - https://eprint.iacr.org/2007/455.pdf

local sha2 = require("tls13.crypto.hash.sha2")

local lib = {}

-- Implementation notes:
--
-- Like with curve25519, instead of using the general-purpose modular arithmetic
-- in tls13.crypto.montgomery, we're exploiting the special form of the prime
-- modulus.

--------------------------------------------------------------------------------
-- Computation in GF(p).
--------------------------------------------------------------------------------

lib.field = {}

-- A field element is stored as a little-endian array of 13 30-bit integers.

-- The field modulus p = 2³⁸⁴ - 2¹²⁸ - 2⁹⁶ + 2³² - 1.
local p = {
  0x3fffffff, 0x00000003, 0x00000000, 0x3fffffc0, 0x3ffffeff,
  0x3fffffff, 0x3fffffff, 0x3fffffff, 0x3fffffff, 0x3fffffff,
  0x3fffffff, 0x3fffffff, 0xffffff,
}

-- Sets a to zero and returns it.
--
-- If a is `nil`, creates a zero element.
local function fieldZero(a)
  a = a or {}

  for i = 1, 13, 1 do
    a[i] = 0
  end

  return a
end

lib.field.fieldZero = fieldZero

-- Sets a to one and returns it.
--
-- If a is `nil`, creates an identity element.
local function fieldOne(a)
  a = a or {}

  for i = 2, 13, 1 do
    a[i] = 0
  end

  a[1] = 1

  return a
end

lib.field.fieldOne = fieldOne

-- Sets b to a.
--
-- If b is `nil`, creates a new element.
local function fieldCopy(b, a)
  b = b or {}

  for i = 1, 13, 1 do
    b[i] = a[i]
  end

  return b
end

lib.field.fieldCopy = fieldCopy

-- Sets c to a if b == 1, or to c if b == 0.
local function fieldCmov(c, a, b)
  for i = 1, 13, 1 do
    local ci = c[i]
    c[i] = ci ~ (ci ~ a[i]) & -b
  end
end

-- Sets c to a + b.
--
-- Assumes a, b ≤ (1 << 390) - 1.
--
-- The output is bounded by p + 2^135 + 2^104 - 2^39 + 2^7 - 2^2 < 2p,
-- given a = b = (1 << 390) - 1.
local function fieldAdd(c, a, b)
  local carry = 0

  for i = 1, 12, 1 do
    local word = a[i] + b[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    -- no need for sign extension: we're doing unsigned arithmetic
  end

  -- reduce everything above 24 bits.
  local word = a[13] + b[13] + carry
  c[13] = word & 0xffffff
  carry = word >> 24

  c[2] = c[2] - (carry << 2) -- bit 32
  c[4] = c[4] + (carry << 6) -- bit 96
  c[5] = c[5] + (carry << 8) -- bit 128

  -- carry propagation, once more.
  -- at the beginning of the loop the carry is going to be added to the least
  -- significant word, corresponding to the bit 0 of the modulus.
  for i = 1, 13, 1 do
    local word = c[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    -- signed because we had to subtract.
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  return c
end

-- p * 2⁹. Used for subtraction.
local prs9 = {
  0x3ffffe00, 0x000007ff, 0x00000000, 0x3fff8000, 0x3ffdffff,
  0x3fffffff, 0x3fffffff, 0x3fffffff, 0x3fffffff, 0x3fffffff,
  0x3fffffff, 0x3fffffff, 0x1ffffffff,
}

-- Sets c to a - b.
--
-- Assumes a, b < (1 << 390) - 1.
--
-- Output is bounded by p - 2**134 - 2**102 + 2**38 - 2**6 + 1 < 2p,
-- given a = 0, b = (1 << 390) - 1.
local function fieldSub(c, a, b)
  local carry = 0

  for i = 1, 12, 1 do
    -- a bit of a hack: instead of subtracting b, we add p * 2⁹ - b.
    -- this is congruent to the expected result but makes sure the most
    -- significant word of c is positive after the 13th iteration (spelled out
    -- below the loop).
    local word = a[i] - b[i] + prs9[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    -- the carries here still have to be signed, though.
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  local word = a[13] - b[13] + prs9[13] + carry
  c[13] = word & 0xffffff
  carry = word >> 24
  -- this carry does not need sign extension assuming the input boudns are
  -- satisfied.

  c[2] = c[2] - (carry << 2) -- bit 32
  c[4] = c[4] + (carry << 6) -- bit 96
  c[5] = c[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = c[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  return c
end

-- Sets c to a * b.
--
-- Assumes a, b < (1 << 390) - 1.
local function fieldMul(c, a, b)
  local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13 =
    table.unpack(a, 1, 13)
  local b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13 =
    table.unpack(b, 1, 13)

  -- first, do regular multiplication.
  local d = {
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

    -- this sum is bounded by
    --   13 * 2^60 - 2^35 + 2^33 - 2^31 + 2^4 - 2^2 + 1,
    -- which is slightly less than 2^64.
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
  }

  -- the largest possible carry is 0x2fffffff3 after reducing the 12th term and
  -- 0x33ffffff2 < 2^35 after the 13th.
  -- so the word will never overflow during propagation.
  -- (but it might get negative. carries must be unsigned.)
  local carry = 0

  for i = 1, 25, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  -- the carry is the 26th word of the intermediate result.

  local i = 26

  -- the next step is modular reduction. first, we process the high-order words
  -- (14 to 26). the 13th word needs special handling.
  repeat
    -- in reverse order for convenience.

    -- 2^((13 + k) * 30) ≡
    --     2^((13 + k -  9) * 30 + 14)
    --   + 2^((13 + k - 10) * 30 + 12)
    --   - 2^((13 + k - 12) * 30 + 8)
    --   + 2^((13 + k - 13) * 30 + 6).
    -- this follows from the form of the modulus.
    d[i - 9] = d[i - 9] + (carry << 14)
    d[i - 10] = d[i - 10] + (carry << 12)
    d[i - 12] = d[i - 12] - (carry << 8)
    d[i - 13] = d[i - 13] + (carry << 6)

    i = i - 1
    carry = d[i]
  until i == 13

  -- the high-order words are no longer significant, so we can start preparing
  -- the actual result (in c).

  -- propagate carries to the 13th word. because we did a subtraction above,
  -- we must perform arithmetic shifts.
  carry = 0

  for i = 1, 12, 1 do
    local word = d[i] + carry
    c[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  local word = d[13] + carry
  c[13] = word & 0xffffff
  carry = word >> 24
  carry = carry | -(carry & 1 << 63 >> 24)

  -- we do the final elimination of p now that we know the factor.
  -- the carry can be negative and up to 20800 in magnitude (I think).
  c[2] = c[2] - (carry << 2) -- bit 32
  c[4] = c[4] + (carry << 6) -- bit 96
  c[5] = c[5] + (carry << 8) -- bit 128

  -- finally, do carry propagation for the last time.
  for i = 1, 13, 1 do
    local word = c[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

lib.field.fieldMul = fieldMul

-- Sets b to a^2.
--
-- Assumes a < (1 << 390) - 1.
local function fieldSq(b, a)
  local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13 =
    table.unpack(a, 1, 13)

  local d = {
    a1 * a1,
    a1 * a2 << 1,
    (a1 * a3 << 1) + a2 * a2,
    a1 * a4 + a2 * a3 << 1,
    (a1 * a5 + a2 * a4 << 1) + a3 * a3,
    a1 * a6 + a2 * a5 + a3 * a4 << 1,
    (a1 * a7 + a2 * a6 + a3 * a5 << 1) + a4 * a4,
    a1 * a8 + a2 * a7 + a3 * a6 + a4 * a5 << 1,
    (a1 * a9 + a2 * a8 + a3 * a7 + a4 * a6 << 1) + a5 * a5,
    a1 * a10 + a2 * a9 + a3 * a8 + a4 * a7 + a5 * a6 << 1,
    (a1 * a11 + a2 * a10 + a3 * a9 + a4 * a8 + a5 * a7 << 1) + a6 * a6,
    a1 * a12 + a2 * a11 + a3 * a10 + a4 * a9 + a5 * a8 + a6 * a7 << 1,
    (a1 * a13 + a2 * a12 + a3 * a11 + a4 * a10 + a5 * a9 + a6 * a8 << 1)
      + a7 * a7,
    a2 * a13 + a3 * a12 + a4 * a11 + a5 * a10 + a6 * a9 + a7 * a8 << 1,
    (a3 * a13 + a4 * a12 + a5 * a11 + a6 * a10 + a7 * a9 << 1) + a8 * a8,
    a4 * a13 + a5 * a12 + a6 * a11 + a7 * a10 + a8 * a9 << 1,
    (a5 * a13 + a6 * a12 + a7 * a11 + a8 * a10 << 1) + a9 * a9,
    a6 * a13 + a7 * a12 + a8 * a11 + a9 * a10 << 1,
    (a7 * a13 + a8 * a12 + a9 * a11 << 1) + a10 * a10,
    a8 * a13 + a9 * a12 + a10 * a11 << 1,
    (a9 * a13 + a10 * a12 << 1) + a11 * a11,
    a10 * a13 + a11 * a12 << 1,
    (a11 * a13 << 1) + a12 * a12,
    a12 * a13 << 1,
    a13 * a13,
  }

  local carry = 0

  for i = 1, 25, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local i = 26

  repeat
    d[i - 9] = d[i - 9] + (carry << 14)
    d[i - 10] = d[i - 10] + (carry << 12)
    d[i - 12] = d[i - 12] - (carry << 8)
    d[i - 13] = d[i - 13] + (carry << 6)

    i = i - 1
    carry = d[i]
  until i == 13

  carry = 0

  for i = 1, 12, 1 do
    local word = d[i] + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  local word = d[13] + carry
  b[13] = word & 0xffffff
  carry = word >> 24
  carry = carry | -(carry & 1 << 63 >> 24)

  b[2] = b[2] - (carry << 2) -- bit 32
  b[4] = b[4] + (carry << 6) -- bit 96
  b[5] = b[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = b[i] + carry

    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

-- Sets b to 2 * a.
--
-- Assumes a < (1 << 390) - 1.
local function fieldMul2(b, a)
  local carry = 0

  for i = 1, 12, 1 do
    local word = (a[i] << 1) + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = (a[13] << 1) + carry
  b[13] = word & 0xffffff
  carry = word >> 24

  b[2] = b[2] - (carry << 2) -- bit 32
  b[4] = b[4] + (carry << 6) -- bit 96
  b[5] = b[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = b[i] + carry

    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

-- Sets c to a * b, where b is a 30-bit word.
--
-- Assumes a < (1 << 390) - 1.
local function fieldMulWord(c, a, b)
  local carry = 0

  for i = 1, 12, 1 do
    local word = a[i] * b + carry
    c[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = a[13] * b + carry
  c[13] = word & 0xffffff
  carry = word >> 24

  c[2] = c[2] - (carry << 2) -- bit 32
  c[4] = c[4] + (carry << 6) -- bit 96
  c[5] = c[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = c[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

-- Sets b to 3 * a.
--
-- Assumes a < (1 << 390) - 1.
local function fieldMul3(b, a)
  return fieldMulWord(b, a, 3)
end

-- Sets b to 4 * a.
--
-- Assumes a < (1 << 390) - 1.
local function fieldMul4(b, a)
  local carry = 0

  for i = 1, 12, 1 do
    local word = (a[i] << 2) + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = (a[13] << 2) + carry
  b[13] = word & 0xffffff
  carry = word >> 24

  b[2] = b[2] - (carry << 2) -- bit 32
  b[4] = b[4] + (carry << 6) -- bit 96
  b[5] = b[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = b[i] + carry

    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

lib.field.fieldMul4 = fieldMul4

-- Sets b to 8 * a.
--
-- Assumes a < (1 << 390) - 1.
local function fieldMul8(b, a)
  local carry = 0

  for i = 1, 12, 1 do
    local word = (a[i] << 3) + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = (a[13] << 3) + carry
  b[13] = word & 0xffffff
  carry = word >> 24

  b[2] = b[2] - (carry << 2) -- bit 32
  b[4] = b[4] + (carry << 6) -- bit 96
  b[5] = b[5] + (carry << 8) -- bit 128

  for i = 1, 13, 1 do
    local word = b[i] + carry

    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end
end

-- For inputs bounded by 2p, performs full modular reduction and
-- sets b to a % p.
--
-- Returns 1 if a < p, and 0 otherwise.
local function fieldReduceQuick(b, a)
  -- a minus p
  local amp = {}

  local borrow = 0

  for i = 1, 13, 1 do
    local word = a[i] - p[i] - borrow

    amp[i] = word & 0x3fffffff

    -- since we're doing a plain 2-argument subtraction, borrow cannot be
    -- greater than one, so we can just use the sign bit.
    borrow = word >> 63
  end

  fieldCopy(b, a)
  -- borrow is either 0 or 1. if it's 1, we don't want to touch b, as a < p in
  -- that case. thus we flip the bit so we can use fieldCmov.
  fieldCmov(b, amp, borrow ~ 0x1)

  return borrow
end

lib.field.fieldReduceQuick = fieldReduceQuick

-- Performs full reduction modulo p. Sets b to a % p.
--
-- Assumes a < (1 << 390) - 1.
local function fieldReduceFull(b, a)
  local word = a[13]
  b[13] = word & 0xffffff
  local carry = word >> 24

  b[2] = a[2] - (carry << 2) -- bit 32
  b[4] = a[4] + (carry << 6) -- bit 96
  b[5] = a[5] + (carry << 8) -- bit 128

  word = a[1] + carry
  b[1] = word & 0x3fffffff
  carry = word >> 30
  carry = carry | -(carry & 1 << 63 >> 30)

  word = b[2] + carry
  b[2] = word & 0x3fffffff
  carry = word >> 30
  carry = carry | -(carry & 1 << 63 >> 30)

  word = a[3] + carry
  b[3] = word & 0x3fffffff
  carry = word >> 30
  carry = carry | -(carry & 1 << 63 >> 30)

  word = b[4] + carry
  b[4] = word & 0x3fffffff
  carry = word >> 30
  carry = carry | -(carry & 1 << 63 >> 30)

  word = b[5] + carry
  b[5] = word & 0x3fffffff
  carry = word >> 30
  carry = carry | -(carry & 1 << 63 >> 30)

  for i = 6, 13, 1 do
    word = a[i] + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  fieldReduceQuick(b, b)
end

-- Sets b to a^-1 modulo p.
local function fieldInvert(b, a)
  local t1, t2, t3, t4 = {}, {}, {}, {}

  fieldSq(b, a) -- b = a^2
  fieldMul(b, a, b) -- b = a^3
  fieldSq(b, b) -- b = a^6
  fieldMul(t2, a, b) -- t2 = a^7
  fieldSq(b, t2) -- b = a^14
  fieldSq(b, b) -- b = a^28
  fieldSq(b, b) -- b = a^56
  fieldMul(b, t2, b) -- b = a^63
  fieldSq(t1, b) -- t1 = a^126

  for i = 1, 5, 1 do
    fieldSq(t1, t1)
  end
  -- t1 = a^4032

  fieldMul(t1, b, t1) -- t1 = a^0xfff
  fieldSq(t3, t1) -- t3 = a^0x1ffe

  for i = 1, 11, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = a^0xfff000

  fieldMul(t1, t1, t3) -- t1 = a^0xffffff

  for i = 1, 6, 1 do
    fieldSq(t1, t1)
  end
  -- t1 = a^0x3fffffc0

  fieldMul(b, b, t1) -- b = a^0x3fffffff
  fieldSq(t1, b) -- t1 = a^0x7ffffffe
  fieldMul(t3, a, t1) -- t3 = a^0x7fffffff
  fieldSq(t1, t3) -- t1 = a^0xfffffffe
  fieldMul(t1, a, t1) -- t1 = a^0xffffffff
  fieldSq(t4, t1) -- t4 = a^0x1fffffffe

  for i = 1, 30, 1 do
    fieldSq(t4, t4)
  end
  -- t4 = a^0x7fffffff80000000

  fieldMul(t3, t3, t4) -- t3 = a^0x7fffffffffffffff
  fieldSq(t4, t3) -- t4 = a^0xfffffffffffffffe

  for i = 1, 62, 1 do
    fieldSq(t4, t4)
  end
  -- t4 = a^0x3fffffffffffffff8000000000000000

  fieldMul(t3, t3, t4) -- t3 = a^0x3fffffffffffffffffffffffffffffff
  fieldSq(t4, t3) -- t4 = a^0x7ffffffffffffffffffffffffffffffe

  for i = 1, 125, 1 do
    fieldSq(t4, t4)
  end
  -- t4 = a^0xfffffffffffffffffffffffffffffffc0000000000000000000000000000000

  fieldMul(t3, t3, t4)
  -- t3 = a^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

  for i = 1, 3, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = a^0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff8

  fieldMul(t2, t2, t3)
  -- t2 = a^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

  for i = 1, 33, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = a^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe00000000

  fieldMul(t1, t1, t2)
  -- t1 = a^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff

  for i = 1, 94, 1 do
    fieldSq(t1, t1)
  end
  -- t1 = a^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc00000000000000000000000

  fieldMul(b, b, t1)
  -- b = a^0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffffffc0000000000000003fffffff
  fieldSq(b, b)
  -- b = a^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7fffffff80000000000000007ffffffe
  fieldSq(b, b)
  -- b = a^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffc
  fieldMul(b, a, b)
  -- b = a^0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000fffffffd
  --   = 2^(p - 2)
end

-- Returns 1 if a = 0, and 0 otherwise.
--
-- Assumes a < 2p.
local function fieldZeroFlag(a)
  local b = {}
  fieldReduceQuick(b, a)

  local bits = 0

  for i = 1, 13, 1 do
    bits = bits | b[i]
  end

  -- if a is zero, bits == 0, so -bits == 0.
  -- otherwise, bits is less than 2³⁰, so -bits is negative.
  return -bits >> 63 ~ 0x1
end

-- Converts a to a big-endian byte string.
local function fieldToBytes(a)
  local b = {}
  fieldReduceFull(b, a)

  return (">I8I8I8I8I8I8"):pack(
    a[11] >> 20 | a[12] << 10 | a[13] << 40,
    a[9] >> 16 | a[10] << 14 | a[11] << 44,
    a[7] >> 12 | a[8] << 18 | a[9] << 48,
    a[5] >> 8 | a[6] << 22 | a[7] << 52,
    a[3] >> 4 | a[4] << 26 | a[5] << 56,
    a[1] | a[2] << 30 | a[3] << 60
  )
end

-- Creates a field element from a byte string.
local function fieldFromBytes(s)
  local a13 = (">I3"):unpack(s, 1)
  local a12 = (">I4"):unpack(s, 4) >> 2
  local a11hi = (">I2"):unpack(s, 7) & (1 << 10) - 1
  local a11lo = (">I3"):unpack(s, 9) >> 4
  local a10 = (">I5"):unpack(s, 11) >> 6 & 0x3fffffff
  local a9hi = (">I2"):unpack(s, 15) & (1 << 14) - 1
  local a9lo = (">I2"):unpack(s, 17)
  local a8 = (">I4"):unpack(s, 19) >> 2
  local a7hi = (">I3"):unpack(s, 22) & (1 << 18) - 1
  local a7lo = (">I2"):unpack(s, 25) >> 4
  local a6 = (">I5"):unpack(s, 26) >> 6 & 0x3fffffff
  local a5hi = (">I3"):unpack(s, 30) & (1 << 22) - 1
  local a5lo = (">I1"):unpack(s, 33)
  local a4 = (">I4"):unpack(s, 34) >> 2
  local a3hi = (">I4"):unpack(s, 37) & (1 << 26) - 1
  local a3lo = (">I1"):unpack(s, 41) >> 4
  local a2 = (">I5"):unpack(s, 41) >> 6 & 0x3fffffff
  local a1 = (">I4"):unpack(s, 45) & 0x3fffffff

  return {
    a1,
    a2,
    a3hi << 4 | a3lo,
    a4,
    a5hi << 8 | a5lo,
    a6,
    a7hi << 12 | a7lo,
    a8,
    a9hi << 16 | a9lo,
    a10,
    a11hi << 20 | a11lo,
    a12,
    a13,
  }
end

lib.field.fieldFromBytes = fieldFromBytes

--------------------------------------------------------------------------------
-- Computation in GF(order), the field of scalars.
--------------------------------------------------------------------------------

lib.scalar = {}

-- The representation is identical to the previous field.

-- The order of the EC group:
--   2³⁸⁴ - 0x389cb27e0bc8d220a7e5f24db74f58851313e695333ad68d.
--
-- Since the cofactor is 1, this is also the order of the base point G.
local order = {
  0x0cc52973, 0x33b065ab, 0x0b0a77ae, 0x06836c92, 0x372ddf58,
  0x0d3607d0, 0x3ffffc76, 0x3fffffff, 0x3fffffff, 0x3fffffff,
  0x3fffffff, 0x3fffffff, 0xffffff,
}

-- The order of the EC group times 2⁹. Used for subtraction.
local orderrs9 = {
  0x0a52e600, 0x20cb5666, 0x14ef5d9d, 0x06d92458, 0x1bbeb034,
  0x2c0fa1b9, 0x3ff8ec69, 0x3fffffff, 0x3fffffff, 0x3fffffff,
  0x3fffffff, 0x3fffffff, 0x1ffffffff,
}

local scalarZero = fieldZero
local scalarOne = fieldOne
local scalarCopy = fieldCopy
local scalarCmov = fieldCmov

lib.scalar.scalarZero = scalarZero
lib.scalar.scalarOne = scalarOne
lib.scalar.scalarCopy = scalarCopy
lib.scalar.scalarCmov = scalarCmov

-- Decodes a scalar from a byte string s.
--
-- s must be not longer than 48 bytes long. The encoding is big-endian.
local function scalarFromBytes(s)
  if #s > 48 then
    return nil, "invalid scalar length"
  end

  return fieldFromBytes(("\0"):rep(48 - #s) .. s)
end

lib.scalar.scalarFromBytes = scalarFromBytes

-- Assuming a < 2 * order, sets b to a % order.
--
-- Returns 1 if a < order, and 0 otherwise.
local function scalarReduceQuick(b, a)
  -- a minus order
  local amorder = {}

  local borrow = 0

  for i = 1, 13, 1 do
    local word = a[i] - order[i] - borrow
    amorder[i] = word & 0x3fffffff
    borrow = word >> 63
  end

  scalarCopy(b, a)
  scalarCmov(b, amorder, borrow ~ 0x1)

  return borrow
end

lib.scalar.scalarReduceQuick = scalarReduceQuick

-- Sets c to a - b.
local function scalarSub(c, a, b)
  local carry = 0

  for i = 1, 12, 1 do
    local word = a[i] - b[i] + orderrs9[i] + carry

    c[i] = word & 0x3fffffff
    carry = word >> 30
    carry = carry | -(carry & 1 << 63 >> 30)
  end

  local word = a[13] - b[13] + orderrs9[13] + carry
  c[13] = word & 0xffffff
  carry = word >> 24

  c[1] = c[1] + carry * 0x333ad68d
  c[2] = c[2] + carry * 0xc4f9a54
  c[3] = c[3] + carry * 0x34f58851
  c[4] = c[4] + carry * 0x397c936d
  c[5] = c[5] + carry * 0x8d220a7
  c[6] = c[6] + carry * 0x32c9f82f
  c[7] = c[7] + carry * 0x389

  carry = 0

  for i = 1, 13, 1 do
    local word = c[i] + carry
    c[i] = word & 0x3fffffff
    carry = word >> 30
  end
end

lib.scalar.scalarSub = scalarSub

-- Sets c to a * b.
local function scalarMul(c, a, b)
  local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13 =
    table.unpack(a, 1, 13)
  local b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13 =
    table.unpack(b, 1, 13)

  local d = {
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
  }

  local carry = 0

  for i = 1, 25, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local i = 26

  repeat
    -- from 2^384 ≡ 0x389cb27e0bc8d220a7e5f24db74f58851313e695333ad68d
    -- it follows that
    --   2^390 ≡ 0xe272c9f82f2348829f97c936dd3d62144c4f9a54cceb5a340.
    d[i - 7] = d[i - 7] + carry * 0xe272
    d[i - 8] = d[i - 8] + carry * 0x327e0bc8
    d[i - 9] = d[i - 9] + carry * 0x348829f9
    d[i - 10] = d[i - 10] + carry * 0x1f24db74
    d[i - 11] = d[i - 11] + carry * 0x3d62144c
    d[i - 12] = d[i - 12] + carry * 0x13e69533
    d[i - 13] = d[i - 13] + carry * 0xeb5a340

    i = i - 1
    carry = d[i]
  until i == 19

  -- doing another iteration may cause overflows in carries, so we must
  -- propagate them already.
  carry = 0

  for i = 20 - 13, 19, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  d[20] = carry
  i = 20

  repeat
    d[i - 7] = d[i - 7] + carry * 0xe272
    d[i - 8] = d[i - 8] + carry * 0x327e0bc8
    d[i - 9] = d[i - 9] + carry * 0x348829f9
    d[i - 10] = d[i - 10] + carry * 0x1f24db74
    d[i - 11] = d[i - 11] + carry * 0x3d62144c
    d[i - 12] = d[i - 12] + carry * 0x13e69533
    d[i - 13] = d[i - 13] + carry * 0xeb5a340

    i = i - 1
    carry = d[i]
  until i == 13

  carry = 0

  for i = 1, 12, 1 do
    local word = d[i] + carry
    c[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = d[13] + carry
  c[13] = word & 0xffffff
  carry = word >> 24

  -- use 2^384 ≡ 0x389cb27e0bc8d220a7e5f24db74f58851313e695333ad68d.
  c[1] = c[1] + carry * 0x333ad68d
  c[2] = c[2] + carry * 0xc4f9a54
  c[3] = c[3] + carry * 0x34f58851
  c[4] = c[4] + carry * 0x397c936d
  c[5] = c[5] + carry * 0x8d220a7
  c[6] = c[6] + carry * 0x32c9f82f
  c[7] = c[7] + carry * 0x389

  carry = 0

  for i = 1, 13, 1 do
    local word = c[i] + carry
    c[i] = word & 0x3fffffff
    carry = word >> 30
  end
end

lib.scalar.scalarMul = scalarMul

-- Sets b to a^2.
local function scalarSq(b, a)
  local a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13 =
    table.unpack(a, 1, 13)

  local d = {
    a1 * a1,
    a1 * a2 << 1,
    (a1 * a3 << 1) + a2 * a2,
    a1 * a4 + a2 * a3 << 1,
    (a1 * a5 + a2 * a4 << 1) + a3 * a3,
    a1 * a6 + a2 * a5 + a3 * a4 << 1,
    (a1 * a7 + a2 * a6 + a3 * a5 << 1) + a4 * a4,
    a1 * a8 + a2 * a7 + a3 * a6 + a4 * a5 << 1,
    (a1 * a9 + a2 * a8 + a3 * a7 + a4 * a6 << 1) + a5 * a5,
    a1 * a10 + a2 * a9 + a3 * a8 + a4 * a7 + a5 * a6 << 1,
    (a1 * a11 + a2 * a10 + a3 * a9 + a4 * a8 + a5 * a7 << 1) + a6 * a6,
    a1 * a12 + a2 * a11 + a3 * a10 + a4 * a9 + a5 * a8 + a6 * a7 << 1,
    (a1 * a13 + a2 * a12 + a3 * a11 + a4 * a10 + a5 * a9 + a6 * a8 << 1)
      + a7 * a7,
    a2 * a13 + a3 * a12 + a4 * a11 + a5 * a10 + a6 * a9 + a7 * a8 << 1,
    (a3 * a13 + a4 * a12 + a5 * a11 + a6 * a10 + a7 * a9 << 1) + a8 * a8,
    a4 * a13 + a5 * a12 + a6 * a11 + a7 * a10 + a8 * a9 << 1,
    (a5 * a13 + a6 * a12 + a7 * a11 + a8 * a10 << 1) + a9 * a9,
    a6 * a13 + a7 * a12 + a8 * a11 + a9 * a10 << 1,
    (a7 * a13 + a8 * a12 + a9 * a11 << 1) + a10 * a10,
    a8 * a13 + a9 * a12 + a10 * a11 << 1,
    (a9 * a13 + a10 * a12 << 1) + a11 * a11,
    a10 * a13 + a11 * a12 << 1,
    (a11 * a13 << 1) + a12 * a12,
    a12 * a13 << 1,
    a13 * a13,
  }

  local carry = 0

  for i = 1, 25, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local i = 26

  repeat
    d[i - 7] = d[i - 7] + carry * 0xe272
    d[i - 8] = d[i - 8] + carry * 0x327e0bc8
    d[i - 9] = d[i - 9] + carry * 0x348829f9
    d[i - 10] = d[i - 10] + carry * 0x1f24db74
    d[i - 11] = d[i - 11] + carry * 0x3d62144c
    d[i - 12] = d[i - 12] + carry * 0x13e69533
    d[i - 13] = d[i - 13] + carry * 0xeb5a340

    i = i - 1
    carry = d[i]
  until i == 19

  carry = 0

  for i = 20 - 13, 19, 1 do
    local word = d[i] + carry
    d[i] = word & 0x3fffffff
    carry = word >> 30
  end

  d[20] = carry
  i = 20

  repeat
    d[i - 7] = d[i - 7] + carry * 0xe272
    d[i - 8] = d[i - 8] + carry * 0x327e0bc8
    d[i - 9] = d[i - 9] + carry * 0x348829f9
    d[i - 10] = d[i - 10] + carry * 0x1f24db74
    d[i - 11] = d[i - 11] + carry * 0x3d62144c
    d[i - 12] = d[i - 12] + carry * 0x13e69533
    d[i - 13] = d[i - 13] + carry * 0xeb5a340

    i = i - 1
    carry = d[i]
  until i == 13

  carry = 0

  for i = 1, 12, 1 do
    local word = d[i] + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
  end

  local word = d[13] + carry
  b[13] = word & 0xffffff
  carry = word >> 24

  b[1] = b[1] + carry * 0x333ad68d
  b[2] = b[2] + carry * 0xc4f9a54
  b[3] = b[3] + carry * 0x34f58851
  b[4] = b[4] + carry * 0x397c936d
  b[5] = b[5] + carry * 0x8d220a7
  b[6] = b[6] + carry * 0x32c9f82f
  b[7] = b[7] + carry * 0x389

  carry = 0

  for i = 1, 13, 1 do
    local word = b[i] + carry
    b[i] = word & 0x3fffffff
    carry = word >> 30
  end
end

lib.scalar.scalarSq = scalarSq

-- Sets b to a^(2^n).
--
-- Assumes n > 0.
local function scalarRepeatedSq(b, a, n)
  scalarSq(b, a)

  for i = 2, n, 1 do
    scalarSq(b, b)
  end
end

-- Sets b to a^-1.
local function scalarInvert(b, a)
  local t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11 =
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}

  -- computes b = a^(order - 2) with an elaborate chain of multiplications and
  -- squarings. you can use script/evaluate-chain.py to check its correctness.
  scalarSq(t4, a)
  scalarMul(t2, a, t4)
  scalarMul(t1, t4, t2)
  scalarMul(t3, t4, t1)
  scalarMul(t5, t4, t3)
  scalarMul(b, t4, t5)
  scalarMul(t6, t4, b)
  scalarMul(t4, t4, t6)
  scalarSq(t7, t4)
  scalarMul(t7, a, t7)
  scalarSq(t9, t7)
  scalarSq(t9, t9)
  scalarSq(t10, t9)
  scalarSq(t8, t10)
  scalarRepeatedSq(t11, t8, 5)
  scalarMul(t8, t8, t11)
  scalarRepeatedSq(t11, t8, 10)
  scalarMul(t8, t8, t11)
  scalarRepeatedSq(t11, t8, 4)
  scalarMul(t10, t10, t11)
  scalarRepeatedSq(t10, t10, 21)
  scalarMul(t8, t8, t10)
  scalarRepeatedSq(t10, t8, 3)
  scalarMul(t9, t9, t10)
  scalarRepeatedSq(t9, t9, 47)
  scalarMul(t8, t8, t9)
  scalarRepeatedSq(t9, t8, 95)
  scalarMul(t8, t8, t9)
  scalarMul(t8, t4, t8)
  scalarRepeatedSq(t8, t8, 6)
  scalarMul(t8, t3, t8)
  scalarRepeatedSq(t8, t8, 3)
  scalarMul(t8, t2, t8)
  scalarRepeatedSq(t8, t8, 7)
  scalarMul(t8, t6, t8)
  scalarRepeatedSq(t8, t8, 6)
  scalarMul(t8, t6, t8)
  scalarSq(t8, t8)
  scalarMul(t8, a, t8)
  scalarRepeatedSq(t8, t8, 11)
  scalarMul(t8, t7, t8)
  scalarSq(t8, t8)
  scalarSq(t8, t8)
  scalarMul(t8, a, t8)
  scalarRepeatedSq(t8, t8, 8)
  scalarMul(t8, t6, t8)
  scalarSq(t8, t8)
  scalarSq(t8, t8)
  scalarMul(t8, t2, t8)
  scalarRepeatedSq(t8, t8, 6)
  scalarMul(t8, b, t8)
  scalarRepeatedSq(t8, t8, 4)
  scalarMul(t8, t3, t8)
  scalarRepeatedSq(t8, t8, 6)
  scalarMul(t7, t7, t8)
  scalarRepeatedSq(t7, t7, 5)
  scalarMul(t7, b, t7)
  scalarRepeatedSq(t7, t7, 10)
  scalarMul(t7, t6, t7)
  scalarRepeatedSq(t7, t7, 9)
  scalarMul(t6, t6, t7)
  scalarRepeatedSq(t6, t6, 4)
  scalarMul(t6, b, t6)
  scalarRepeatedSq(t6, t6, 6)
  scalarMul(t5, t5, t6)
  scalarRepeatedSq(t5, t5, 3)
  scalarMul(t5, a, t5)
  scalarRepeatedSq(t5, t5, 7)
  scalarMul(t5, b, t5)
  scalarRepeatedSq(t5, t5, 7)
  scalarMul(t5, t1, t5)
  scalarRepeatedSq(t5, t5, 5)
  scalarMul(t5, t3, t5)
  scalarRepeatedSq(t5, t5, 5)
  scalarMul(t4, t4, t5)
  scalarRepeatedSq(t4, t4, 5)
  scalarMul(t4, b, t4)
  scalarRepeatedSq(t4, t4, 4)
  scalarMul(t4, b, t4)
  scalarRepeatedSq(t4, t4, 5)
  scalarMul(t3, t3, t4)
  scalarRepeatedSq(t3, t3, 3)
  scalarMul(t3, t2, t3)
  scalarRepeatedSq(t3, t3, 7)
  scalarMul(t3, t2, t3)
  scalarRepeatedSq(t3, t3, 6)
  scalarMul(t3, b, t3)
  scalarRepeatedSq(t3, t3, 4)
  scalarMul(t3, t1, t3)
  scalarRepeatedSq(t3, t3, 3)
  scalarMul(t3, t2, t3)
  scalarRepeatedSq(t3, t3, 4)
  scalarMul(t3, t2, t3)
  scalarRepeatedSq(t3, t3, 4)
  scalarMul(t2, t2, t3)
  scalarRepeatedSq(t2, t2, 6)
  scalarMul(t2, t1, t2)
  scalarRepeatedSq(t2, t2, 5)
  scalarMul(t1, t1, t2)
  scalarRepeatedSq(t1, t1, 6)
  scalarMul(b, b, t1)
  scalarSq(b, b)
  scalarMul(b, a, b)
  scalarRepeatedSq(b, b, 4)
  scalarMul(b, a, b)
end

lib.scalar.scalarInvert = scalarInvert

-- Returns 1 if a < order, otherwise 0.
local function scalarCanonicalFlag(a)
  return scalarReduceQuick({}, a)
end

-- Returns `true` iff a is congruent to zero.
--
-- Assumes a < 2 * order.
local function scalarIsZero(a)
  local b = {}
  scalarReduceQuick(b, a)

  for i = 1, 13, 1 do
    if b[i] ~= 0 then
      return false
    end
  end

  return true
end

lib.scalar.scalarIsZero = scalarIsZero

--------------------------------------------------------------------------------
-- Computation in the EC group.
--------------------------------------------------------------------------------

lib.group = {}

-- A group element is represented in Jacobian coordinates (X, Y, Z such that
-- x = X / Z² and y = Y / Z³).

-- Formulas:
-- http://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html
-- - double: dbl-2001-b
-- - addition: add-2007-bl
-- - mixed addition: madd-2007-bl

-- The coefficient b in the curve equation y² = x³ - 3x + b.
local b = {
  0x13ec2aef, 0x2a1723b7, 0x22ed19d2, 0x158e6362, 0x13875ac6,
  0x10223d40, 0x14112031, 0x271bbfa0, 0x2d19181d, 0x15af8fe0,
  0x3e4988e0, 0x29f88fb9, 0xb3312f,
}

-- Sets q to the neutral group element (the point at infinity).
--
-- If `q` is nil, creates a new element.
local function groupJacobianZero(q)
  q = q or {}

  q[1] = fieldZero() -- X
  q[2] = fieldZero() -- Y
  q[3] = fieldZero() -- Z

  return q
end

lib.group.groupJacobianZero = groupJacobianZero

-- Sets q to p if b == 1, or q if b == 0.
local function groupCmov(q, p, b)
  fieldCmov(q[1], p[1], b)
  fieldCmov(q[2], p[2], b)
  fieldCmov(q[3], p[3], b)
end

lib.group.groupCmov = groupCmov

-- Sets q to p.
local function groupCopy(q, p)
  fieldCopy(q[1], p[1])
  fieldCopy(q[2], p[2])
  fieldCopy(q[3], p[3])
end

-- Returns 1 if p is the point at infinity, and 0 otherwise.
local function groupJacobianZeroFlag(p)
  return fieldZeroFlag(p[3])
end

lib.group.groupJacobianZeroFlag = groupJacobianZeroFlag

-- Sets q to [2]p.
local function groupJacobianDouble(q, p)
  local x1, y1, z1 = p[1], p[2], p[3]
  local x3, y3, z3 = q[1], q[2], q[3]

  local delta = {}
  fieldSq(delta, z1) -- delta = Z₁²

  local gamma = {}
  fieldSq(gamma, y1) -- gamma = Y₁²

  local beta = {}
  fieldMul(beta, x1, gamma) -- beta = X₁ * gamma

  local x1mdelta = {}
  local alpha = {}
  fieldSub(x1mdelta, x1, delta) -- X₁ - delta
  fieldAdd(alpha, x1, delta) -- X₁ + delta
  fieldMul(alpha, x1mdelta, alpha) -- (X₁ - delta) * (X₁ + delta)
  fieldMul3(alpha, alpha) -- alpha = 3 * (X₁ - delta) * (X₁ + delta)

  fieldAdd(z3, y1, z1) -- Y₁ + Z₁
  fieldSq(z3, z3) -- (Y₁ + Z₁)²
  fieldSub(z3, z3, gamma) -- (Y₁ + Z₁)² - gamma
  fieldSub(z3, z3, delta) -- Z₃ = (Y₁ + Z₁)² - gamma - delta

  fieldMul4(y3, beta) -- 4 * beta
  fieldMul2(beta, y3) -- 8 * beta
  fieldSq(x3, alpha) -- alpha²
  fieldSub(x3, x3, beta) -- X₃ = alpha² - 8 * beta

  fieldSq(gamma, gamma) -- gamma²
  fieldMul8(gamma, gamma) -- 8 * gamma²
  fieldSub(y3, y3, x3) -- 4 * beta - X₃
  fieldMul(y3, alpha, y3) -- alpha * (4 * beta - X₃)
  fieldSub(y3, y3, gamma) -- Y₃ = alpha * (4 * beta - X₃) - 8 * gamma²
end

lib.group.groupJacobianDouble = groupJacobianDouble

-- Sets d to p + q.
--
-- Returns 1 if p.Y = q.Y and 0 otherwise.
--
-- This function may produce the point at infinity even though p + q ≠ 𝕆.
-- This is indicated by the return value of 1, in which case doubling should be
-- used instead. The only other case when the result is incorrect is
-- if either p or q is the point at infinity.
local function groupJacobianAddUnchecked(d, p, q)
  local x1, y1, z1 = p[1], p[2], p[3]
  local x2, y2, z2 = q[1], q[2], q[3]
  local x3, y3, z3 = d[1], d[2], d[3]

  local z1z1, z2z2, u1, u2, s1, s2, h, i, j, r, v =
    {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}

  fieldSq(z1z1, z1) -- Z₁Z₁ = Z₁²
  fieldSq(z2z2, z2) -- Z₂Z₂ = Z₂²

  fieldMul(u1, x1, z2z2) -- U₁ = X₁ * Z₂Z₂
  fieldMul(u2, x2, z1z1) -- U₂ = X₂ * Z₁Z₁

  fieldMul(s1, z2, z2z2) -- Z₂³
  fieldMul(s1, y1, s1) -- S₁ = Y₁ * Z₂³
  fieldMul(s2, z1, z1z1) -- Z₁³
  fieldMul(s2, y2, s2) -- S₂ = Y₂ * Z₁³
  fieldAdd(z3, z1, z2) -- Z₁ + Z₂

  fieldSub(h, u2, u1) -- H = U₂ - U₁
  fieldMul2(i, h) -- 2 * H
  fieldSq(i, i) -- I = (2 * H)²

  fieldMul(j, h, i) -- J = H * I

  fieldSub(r, s2, s1) -- S₂ - S₁
  fieldMul2(r, r) -- r = 2 * (S₂ - S₁)

  fieldMul(v, u1, i) -- V = U₁ * I

  local t2 = {}
  fieldMul2(t2, v) -- 2 * V
  fieldSq(x3, r) -- r²
  fieldSub(x3, x3, j) -- r² - J
  fieldSub(x3, x3, t2) -- X₃ = r² - J - 2 * V

  fieldMul(t2, s1, j) -- S₁ * J
  fieldMul2(t2, t2) -- 2 * S₁ * J
  fieldSub(y3, v, x3) -- V - X₃
  fieldMul(y3, r, y3) -- r * (V - X₃)
  fieldSub(y3, y3, t2) -- Y₃ = r * (V - X₃) - 2 * S₁ * J

  fieldSq(z3, z3) -- (Z₁ + Z₂)²
  fieldSub(z3, z3, z1z1) -- (Z₁ + Z₂)² - Z₁Z₁
  fieldSub(z3, z3, z2z2) -- (Z₁ + Z₂)² - Z₁Z₁ - Z₂Z₂
  fieldMul(z3, z3, h) -- Z₃ = ((Z₁ + Z₂)² - Z₁Z₁ - Z₂Z₂) * H

  -- special cases.
  --
  -- - P = Q. this means Z₃ = 0, H = 0, r = 0, and we're producing the point at
  --   infinity. for this curve, the cofactor of G is 1, which means the group
  --   is cyclic and there's no point of order 2. thus, unless P = Q = 𝕆,
  --   the result is invalid. the function has to return 1.
  --
  -- - P = -Q. this means Z₃ = 0, H = 0, r ≠ 0, and we're producing the point at
  --   infinity. this is correct.
  --
  -- - P = 𝕆 ≠ Q or P ≠ 𝕆 = Q. in both of these cases Z₃ = 0, so we're again
  --   producing the point at infinity. also H ≠ 0, r ≠ 0.
  --   the result is invalid.
  --
  -- thus, we'll return 1 iff r = 0.

  return fieldZeroFlag(r)
end

lib.group.groupJacobianAddUnchecked = groupJacobianAddUnchecked

-- Sets d to p + q.
--
-- Handles all special cases in constant time at the expense of performance.
local function groupJacobianAdd(d, p, q)
  local pt2 = groupJacobianZero()
  groupJacobianDouble(pt2, p)

  local result = groupJacobianZero()

  local moveP = groupJacobianZeroFlag(q)
  local moveQ = groupJacobianZeroFlag(p)
  local sameY = groupJacobianAddUnchecked(result, p, q)
  local needDouble =
    sameY
    & ~(moveP | moveQ)
    & groupJacobianZeroFlag(result)

  -- this handles the case of p or q being zero.
  groupCmov(result, p, moveP)
  groupCmov(result, q, moveQ)
  groupCopy(d, result)

  -- now, if we had to do doubling after all, we use that.
  groupCmov(d, pt2, needDouble)
end

lib.group.groupJacobianAdd = groupJacobianAdd

-- Sets d to r - q.
--
-- Handles all special cases in constant time at the expense of performance.
local function groupJacobianSub(d, r, q)
  local mq = {q[1], {}, q[3]}
  fieldSub(mq[2], p, q[2])
  groupJacobianAdd(d, r, mq)
end

lib.group.groupJacobianSub = groupJacobianSub

-- Decodes an EC point p from its uncompressed representation s.
--
-- Returns 1 if the key is invalid. Returns `nil, err` if decoding fails.
-- Otherwise returns 0.
local function groupJacobianFromBytes(p, s)
  if #s ~= 1 + 2 * 48 then
    return nil, "invalid point"
  end

  local format = s:byte(1)

  if format ~= 0x04 then
    return nil, "unsupported format"
  end

  local x = s:sub(2, 49)
  local y = s:sub(50)

  x = fieldFromBytes(x)
  y = fieldFromBytes(y)

  -- if canonical is 0, the key is invalid.
  local canonical = fieldReduceQuick({}, x) & fieldReduceQuick({}, y)

  -- check the curve equation.
  local y2 = {}
  local rhs = {}

  fieldSq(y2, y)
  fieldSq(rhs, x)
  fieldMul(rhs, rhs, x)

  -- xt3 = 3 * x
  local xt3 = {}
  fieldMul3(xt3, x)

  fieldSub(rhs, rhs, xt3)
  fieldAdd(rhs, rhs, b)
  -- rhs = x³ - 3 * x + b

  fieldSub(rhs, rhs, y2)
  local onCurve = fieldZeroFlag(rhs)

  local invalid = canonical & onCurve ~ 0x1

  p[1] = x
  p[2] = y
  p[3] = fieldOne()

  return invalid
end

lib.group.groupJacobianFromBytes = groupJacobianFromBytes

-- Converts an EC point p to affine coordinates and sets the result to q.
local function groupJacobianToAffine(q, p)
  local invz = {}
  local invz2 = {}
  local invz3 = {}

  fieldInvert(invz, p[3])
  fieldSq(invz2, invz)
  fieldMul(invz3, invz2, invz)

  fieldMul(q[1], p[1], invz2)
  fieldMul(q[2], p[2], invz3)
  fieldMul(q[3], p[3], invz)
end

lib.group.groupJacobianToAffine = groupJacobianToAffine

-- Converts an EC point q to its uncompressed representation.
--
-- Assumes q < 2p.
local function groupJacobianToBytes(q)
  local d = {}
  groupJacobianToAffine(d, q)

  return "\x04" .. fieldToBytes(d[1]) .. fieldToBytes(d[2])
end

lib.group.groupJacobianToBytes = groupJacobianToBytes

-- Sets d to p + q, performing mixed addition (i.e., assuming q.Z is 1).
--
-- Returns 1 if p.Y = q.Y and 0 otherwise.
--
-- This function may produce the point at infinity even though p + q ≠ 𝕆.
-- This is indicated by the return value of 1, in which case doubling should be
-- used instead. The only other case when the result is incorrect is
-- if either p or q is the point at infinity.
local function groupJacobianMixedAddUnchecked(d, p, q)
  local x1, y1, z1 = p[1], p[2], p[3]
  local x2, y2 = q[1], q[2]
  local x3, y3, z3 = d[1], d[2], d[3]

  local z1z1, u2, s2, h, hh, i, j, r, v = {}, {}, {}, {}, {}, {}, {}, {}, {}

  fieldSq(z1z1, z1) -- Z₁Z₁ = Z₁²
  fieldMul(u2, x2, z1z1) -- U₂ = X₂ * Z₁Z₁
  fieldMul(s2, y2, z1) -- Y₂ * Z₁
  fieldMul(s2, s2, z1z1) -- S₂ = Y₂ * Z₁ * Z₁Z₁

  fieldSub(h, u2, x1) -- H = U₂ - X₁
  fieldSq(hh, h) -- HH = H²

  fieldMul4(i, hh) -- I = 4 * HH
  fieldMul(j, h, i) -- J = H * I

  fieldSub(r, s2, y1) -- S₂ - Y₁
  fieldMul2(r, r) -- r = 2 * (S₂ - Y₁)

  fieldMul(v, x1, i) -- V = X₁ * I

  local t2 = {}
  fieldMul2(t2, v)

  fieldSq(x3, r) -- r²
  fieldSub(x3, x3, j) -- r² - J
  fieldSub(x3, x3, t2) -- X₃ = r² - J - 2 * V

  fieldSub(y3, v, x3) -- V - X₃
  fieldMul(y3, r, y3) -- r * (V - X₃)
  fieldMul(t2, y1, j) -- Y₁ * J
  fieldMul2(t2, t2) -- 2 * Y₁ * J
  fieldSub(y3, y3, t2) -- Y₃ = r * (V - X₃) - 2 * Y₁ * J

  fieldAdd(z3, z1, h) -- Z₁ + H
  fieldSq(z3, z3) -- (Z₁ + H)²
  fieldSub(z3, z3, z1z1) -- (Z₁ + H)² - Z₁Z₁
  fieldSub(z3, z3, hh) -- Z₃ = (Z₁ + H)² - Z₁Z₁ - HH

  return fieldZeroFlag(r)
end

lib.group.groupJacobianMixedAddUnchecked = groupJacobianMixedAddUnchecked

-- Sets d to p + q, performing mixed addition (i.e. assuming q.Z is 1).
--
-- Handles all special cases in constant time at the expense of performance.
local function groupJacobianMixedAdd(d, p, q)
  local pt2 = groupJacobianZero()
  groupJacobianDouble(pt2, p)

  local result = groupJacobianZero()

  local moveP = groupJacobianZeroFlag(q)
  local moveQ = groupJacobianZeroFlag(p)
  local sameY = groupJacobianMixedAddUnchecked(result, p, q)
  local needDouble =
    sameY
    & ~(moveP | moveQ)
    & groupJacobianZeroFlag(result)

  groupCmov(result, p, moveP)
  groupCmov(result, q, moveQ)
  groupCopy(d, result)
  groupCmov(d, pt2, needDouble)
end

lib.group.groupJacobianMixedAdd = groupJacobianMixedAdd

-- Sets d to r - q, performing mixed addition (i.e. assuming q.Z is 1).
--
-- Handles all special cases in constant time at the expense of performance.
local function groupJacobianMixedSub(d, r, q)
  local mq = {q[1], {}, q[3]}
  fieldSub(mq[2], p, q[2])
  groupJacobianMixedAdd(d, r, mq)
end

lib.group.groupJacobianMixedSub = groupJacobianMixedSub

-- Computes an addition-subtraction chain for multiplication of an EC point
-- by a scalar k. Non-zero entries indicate an addition
-- (subtraction if negative) of a precomputed value.
--
-- k is assumed to be a 384-bit scalar, represented as a 13-array of 30-bit
-- words (same as field elements).
local function getChain(k)
  -- see https://eprint.iacr.org/2007/455.pdf, section 3, for reference.
  local r = {}

  -- initially this is the chain of a naive double-and-add algorithm.
  for i = 0, 383, 1 do
    r[i + 1] = k[i // 30 + 1] >> i % 30 & 0x1
  end

  -- we may have to perform an extra doubling because we subtract.
  r[385] = 0

  -- try to group bits together to reduce the number of additions.
  -- the precomputed points are {-31P, -29P, ..., 29P, 31P}.
  for i = 1, 384, 1 do
    if r[i] == 1 then
      -- the maximum multiple (31) is 5 bits wide. but we want to check 1 extra
      -- bit to make it extra efficient (see the comment below).
      for b = 1, 5, 1 do
        if i + b > 384 then
          break
        elseif r[i + b] == 1 then
          -- try to "glue" this bit to the window index.
          --
          -- e.g., if bit i + 1 is set, we'll be adding (as r[i] == 1) P to the
          -- accumulator, then double and add P once more. but we already have
          -- 3P precomputed, so we can save 1 addition by adding 3P at step i
          -- and skipping the addition at i + 1.
          --
          -- likewise, sometimes it makes sense to *subtract*. imagine we had
          -- 10 bits set in a row. we can, of course, glue together the first
          -- 5 additions (31P), do 5 doubles, followed by another addition of
          -- 31P. but notice what happens if we subtract P instead of adding it.
          -- this now requires us to add 32P -- but that's exactly what's going
          -- to happen anyway when we double. and if we consider the whole
          -- sequence of 10 bits, which told us we'll be adding 1023P, now we
          -- need to add 1024P, which will happen automatically when we do
          -- doubling.
          --
          -- in the end, we first try to add a precomputed point (up to 31P).
          -- if gluing another bit gets us a multiple with a factor larger than
          -- 31, we'll instead subtract by that much (unless we again get a
          -- factor larger than in 31 in magnitude). the subtraction can only
          -- happen when we're looking at the 5th bit from i, which considers
          -- 32P.
          local bit = r[i + b] << b
          local windowIdx = r[i] + bit

          if windowIdx <= 31 then
            r[i] = windowIdx
            r[i + b] = 0
          else
            windowIdx = r[i] - bit

            if windowIdx < -31 then
              break
            end

            r[i] = windowIdx

            for j = i + b, 385, 1 do
              if r[j] == 0 then
                r[j] = 1

                break
              end

              r[j] = 0
            end
          end
        end
      end
    end
  end

  return r
end

-- Prepares an array of {P, 3P, 5P, ..., 31P}.
--
-- Assumes P.Z is 1. Every returned point has Z equal to 1 (or 0).
local function groupDoScalarMultPrecomputation(p)
  local result = {p}

  local pt2 = groupJacobianZero() -- [2]P
  groupJacobianDouble(pt2, p)

  for i = 2, 16, 1 do
    result[i] = groupJacobianZero()
    groupJacobianMixedAdd(result[i], pt2, result[i - 1])
    groupJacobianToAffine(result[i], result[i])
  end

  return result
end

lib.group.groupDoScalarMultPrecomputation = groupDoScalarMultPrecomputation

-- The base point G of the curve.
local g = {
  {
    0x32760ab7, 0x295178e1, 0x355296c3, 0xbc976f, 0x142a3855,
    0x1d078209, 0x39b9859f, 0x0ed8a2e9, 0x2d746e1d, 0x1c7bcc82,
    0x1378eb1c, 0x08afa2c1, 0xaa87ca,
  },
  {
    0x10ea0e5f, 0x290c75f2, 0x17e819d7, 0x182c7387, 0x30b8c00a,
    0x28c44ed7, 0x2147ce9d, 0x076f4a26, 0x1c29f8f4, 0x22fe4a4b,
    0x06f5d9e9, 0x12a5898b, 0x3617de,
  },
  fieldOne(),
}

local gWindow = groupDoScalarMultPrecomputation(g)

-- Given p, an EC point in Jacobian coordinates, and u, v, two 384-bit scalars,
-- represented as arrays of 13 30-bit words, little-endian,
-- sets d to [u]G + [v]q, where G is the curve's base point.
local function groupJacobianDoubleBaseScalarMulAdd(d, p, u, v)
  local pWindow = groupDoScalarMultPrecomputation(p)
  local gChain = getChain(u)
  local pChain = getChain(v)

  groupJacobianZero(d)

  local i = 385

  while i > 1 and gChain[i] == 0 and pChain[i] == 0 do
    i = i - 1
  end

  for i = i, 1, -1 do
    groupJacobianDouble(d, d)

    if gChain[i] > 0 then
      groupJacobianMixedAdd(d, d, gWindow[1 + (gChain[i] >> 1)])
    elseif gChain[i] < 0 then
      groupJacobianMixedSub(d, d, gWindow[1 + (-gChain[i] >> 1)])
    end

    if pChain[i] > 0 then
      groupJacobianMixedAdd(d, d, pWindow[1 + (pChain[i] >> 1)])
    elseif pChain[i] < 0 then
      groupJacobianMixedSub(d, d, pWindow[1 + (-pChain[i] >> 1)])
    end
  end
end

lib.group.groupJacobianDoubleBaseScalarMulAdd =
  groupJacobianDoubleBaseScalarMulAdd

--------------------------------------------------------------------------------
-- ECDSA.
--------------------------------------------------------------------------------

-- Verifies an ECDSA signature (r, s) of a message.
--
-- - message: a byte string.
-- - hash: a hash function.
-- - messageHash: a 384-bit integer as a scalar field element.
-- - r, s: 384-bit integer as scalar field elements.
-- - q: the public key, an EC point in affine coordinates.
--
-- Returns `true` if the signature is accepted, otherwise `false`.
function lib.ecdsaVerifyDecoded(message, hash, r, s, q)
  if scalarCanonicalFlag(r) == 0 or scalarCanonicalFlag(s) == 0 then
    return nil, "invalid signature"
  end

  if scalarIsZero(r) or scalarIsZero(s) then
    return nil, "invalid signature"
  end

  local messageHash = hash():update(message):finish():sub(1, 48)
  local e = scalarFromBytes(messageHash)

  local sInv = {}
  scalarInvert(sInv, s)

  local u, v = {}, {}
  scalarMul(u, e, sInv)
  scalarReduceQuick(u, u)
  scalarMul(v, r, sInv)
  scalarReduceQuick(v, v)

  local p = groupJacobianZero()
  groupJacobianDoubleBaseScalarMulAdd(p, q, u, v)

  if groupJacobianZeroFlag(p) == 1 then
    return nil, "invalid signature"
  end

  groupJacobianToAffine(p, p)
  fieldReduceQuick(p[1], p[1])

  -- r minus x
  local rmx = {}
  scalarSub(rmx, r, p[1])

  if not scalarIsZero(rmx) then
    return nil, "invalid signature"
  end

  return true
end

-- Decodes parameters and verifies an ECDSA signature (r, s) of a message.
--
-- message, sr, ss, sq are byte strings.
function lib.ecdsaVerify(message, hash, sr, ss, sq)
  local r = scalarFromBytes(sr)
  local s = scalarFromBytes(ss)

  if not r then
    return nil, "r is too long"
  end

  if not s then
    return nil, "s is too long"
  end

  local q = groupJacobianZero()
  local invalidFlag, err = groupJacobianFromBytes(q, sq)

  if not invalidFlag then
    return nil, err
  elseif invalidFlag == 1 then
    return nil, "invalid point"
  end

  return lib.ecdsaVerifyDecoded(message, hash, r, s, q)
end

-- Decodes parameters and verifies an ECDSA signature (r, s) of a message using
-- SHA-384 as the signature hash function.
function lib.ecdsaVerifySha384(message, sr, ss, sq)
  return lib.ecdsaVerify(message, sha2.sha384, sr, ss, sq)
end

return lib

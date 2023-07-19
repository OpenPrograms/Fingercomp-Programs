-- The X25519 key exchange function (using Curve25519).
-- Algorithms over an elliptic curve Curve25519:
--
-- - X25519 (key exchange)
-- - Ed25519 (digital signatures)
--
-- Field/group arithmetic operations were ported from libsodium (itself based on
-- ref10) to Lua.
--
-- (For ease of comparison, I'm including source file paths as of 6187ebc
-- in the code.)
--
-- Ref:
-- - libsodium. https://github.com/jedisct1/libsodium
-- - SUPERCOP. http://bench.cr.yp.to/supercop.html
-- - RFC 7748. https://datatracker.ietf.org/doc/html/rfc7748
-- - RFC 8032. https://datatracker.ietf.org/doc/html/rfc8032
-- - D. J. Bernstein. Curve25519: new Diffie-Hellman speed records. https://cr.yp.to/ecdh/curve25519-20060209.pdf

-- libsodium copyright notice:
--
-- /*
--  * ISC License
--  *
--  * Copyright (c) 2013-2023
--  * Frank Denis <j at pureftpd dot org>
--  *
--  * Permission to use, copy, modify, and/or distribute this software for any
--  * purpose with or without fee is hereby granted, provided that the above
--  * copyright notice and this permission notice appear in all copies.
--  *
--  * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
--  * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
--  * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
--  * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
--  * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
--  * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
--  * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
--  */

local util = require("tls13.util")

local sha2 = require("tls13.crypto.hash.sha2")

local lib = {}

--------------------------------------------------------------------------------
-- Computation in GF(2²⁵⁵ - 19), a prime field.
--------------------------------------------------------------------------------

-- Sets h to f.
local function fieldCopy(h, f)
  table.move(f, 1, 10, 1, h)
end

-- The order of the elliptic curve group (little-endian).
local l = util.fromHex(
  "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"
)

-- File: src/libsodium/crypto_core/ed25519/ref10/fe_25_5/constants.h.

-- The square root of -1 in GF(2²⁵⁵ - 19).
local fieldSqrtm1 = {
  -32595792, -7943725, 9377950, 3500415, 12389472,
  -272473, -25146209, -2005654, 326686, 11406482,
}

-- d, a parameter of the twisted Edwards curve edwards25519.
local ed25519d = {
  -10913610, 13857413, -15372611, 6949391, 114729,
  -8787816, -6275908, -3247719, -18696448, -12055116,
}

-- 2 * d, where d is a parameter of the twisted Edwards curve edwards25519.
local ed25519d2 = {
  -21827239, -5839606, -30745221, 13898782, 229458,
  15978800, -12551817, -6495438, 29715968, 9444199,
}

-- File: src/libsodlium/crypto_core/ed25519/ref10/fe_25_5/base2.h.

local constBi = {
  {
    ypx = {
      25967493, -14356035, 29566456, 3660896, -12694345,
      4014787, 27544626, -11754271, -6079156, 2047605,
    },
    ymx = {
      -12545711, 934262, -2722910, 3049990, -727428,
      9406986, 12720692, 5043384, 19500929, -15469378,
    },
    xy2d = {
      -8738181, 4489570, 9688441, -14785194, 10184609,
      -12363380, 29287919, 11864899, -24514362, -4438546,
    }
  },
  {
    ypx = {
      15636291, -9688557, 24204773, -7912398, 616977,
      -16685262, 27787600, -14772189, 28944400, -1550024,
    },
    ymx = {
      16568933, 4717097, -11556148, -1102322, 15682896,
      -11807043, 16354577, -11775962, 7689662, 11199574,
    },
    xy2d = {
      30464156, -5976125, -11779434, -15670865, 23220365,
      15915852, 7512774, 10017326, -17749093, -9920357,
    }
  },
  {
    ypx = {
      10861363, 11473154, 27284546, 1981175, -30064349,
      12577861, 32867885, 14515107, -15438304, 10819380,
    },
    ymx = {
      4708026, 6336745, 20377586, 9066809, -11272109,
      6594696, -25653668, 12483688, -12668491, 5581306,
    },
    xy2d = {
      19563160, 16186464, -29386857, 4097519, 10237984,
      -4348115, 28542350, 13850243, -23678021, -15815942,
    }
  },
  {
    ypx = {
      5153746, 9909285, 1723747, -2777874, 30523605,
      5516873, 19480852, 5230134, -23952439, -15175766,
    },
    ymx = {
      -30269007, -3463509, 7665486, 10083793, 28475525,
      1649722, 20654025, 16520125, 30598449, 7715701,
    },
    xy2d = {
      28881845, 14381568, 9657904, 3680757, -20181635,
      7843316, -31400660, 1370708, 29794553, -1409300,
    }
  },
  {
    ypx = {
      -22518993, -6692182, 14201702, -8745502, -23510406,
      8844726, 18474211, -1361450, -13062696, 13821877,
    },
    ymx = {
      -6455177, -7839871, 3374702, -4740862, -27098617,
      -10571707, 31655028, -7212327, 18853322, -14220951,
    },
    xy2d = {
      4566830, -12963868, -28974889, -12240689, -7602672,
      -2830569, -8514358, -10431137, 2207753, -3209784,
    }
  },
  {
    ypx = {
      -25154831, -4185821, 29681144, 7868801, -6854661,
      -9423865, -12437364, -663000, -31111463, -16132436,
    },
    ymx = {
      25576264, -2703214, 7349804, -11814844, 16472782,
      9300885, 3844789, 15725684, 171356, 6466918,
    },
    xy2d = {
      23103977, 13316479, 9739013, -16149481, 817875,
      -15038942, 8965339, -14088058, -30714912, 16193877,
    }
  },
  {
    ypx = {
      -33521811, 3180713, -2394130, 14003687, -16903474,
      -16270840, 17238398, 4729455, -18074513, 9256800,
    },
    ymx = {
      -25182317, -4174131, 32336398, 5036987, -21236817,
      11360617, 22616405, 9761698, -19827198, 630305,
    },
    xy2d = {
      -13720693, 2639453, -24237460, -7406481, 9494427,
      -5774029, -6554551, -15960994, -2449256, -14291300,
    }
  },
  {
    ypx = {
      -3151181, -5046075, 9282714, 6866145, -31907062,
      -863023, -18940575, 15033784, 25105118, -7894876,
    },
    ymx = {
      -24326370, 15950226, -31801215, -14592823, -11662737,
      -5090925, 1573892, -2625887, 2198790, -15804619,
    },
    xy2d = {
      -3099351, 10324967, -2241613, 7453183, -5446979,
      -2735503, -13812022, -16236442, -32461234, -12290683,
    }
  }
}

-- File: src/libsodium/include/sodium/private/ed25519_ref10_fe25_5.h.

-- Sets h to zero (additive identity).
local function field0(h)
  h = h or {}

  for i = 1, 10, 1 do
    h[i] = 0
  end

  return h
end

-- Sets h to one (multiplicative identity).
local function field1(h)
  h = h or {}

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    1, 0, 0, 0, 0,
    0, 0, 0, 0, 0

  return h
end

-- Sets h to f + g. Does not reduce the output.
local function fieldAdd(h, f, g)
  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    f[1] + g[1],
    f[2] + g[2],
    f[3] + g[3],
    f[4] + g[4],
    f[5] + g[5],
    f[6] + g[6],
    f[7] + g[7],
    f[8] + g[8],
    f[9] + g[9],
    f[10] + g[10]
end

-- Sets h to f - g. Does not reduce the output.
local function fieldSub(h, f, g)
  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    f[1] - g[1],
    f[2] - g[2],
    f[3] - g[3],
    f[4] - g[4],
    f[5] - g[5],
    f[6] - g[6],
    f[7] - g[7],
    f[8] - g[8],
    f[9] - g[9],
    f[10] - g[10]
end

-- Sets h to -f.
local function fieldNeg(h, f)
  h[1] = -f[1]
  h[2] = -f[2]
  h[3] = -f[3]
  h[4] = -f[4]
  h[5] = -f[5]
  h[6] = -f[6]
  h[7] = -f[7]
  h[8] = -f[8]
  h[9] = -f[9]
  h[10] = -f[10]
end

-- Sets f to g if b == 1, or f if b == 0.
local function fieldCmov(f, h, b)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)

  local x1 = f1 ~ h[1]
  local x2 = f2 ~ h[2]
  local x3 = f3 ~ h[3]
  local x4 = f4 ~ h[4]
  local x5 = f5 ~ h[5]
  local x6 = f6 ~ h[6]
  local x7 = f7 ~ h[7]
  local x8 = f8 ~ h[8]
  local x9 = f9 ~ h[9]
  local x10 = f10 ~ h[10]

  x1 = x1 & -b
  x2 = x2 & -b
  x3 = x3 & -b
  x4 = x4 & -b
  x5 = x5 & -b
  x6 = x6 & -b
  x7 = x7 & -b
  x8 = x8 & -b
  x9 = x9 & -b
  x10 = x10 & -b

  f[1] = f1 ~ x1
  f[2] = f2 ~ x2
  f[3] = f3 ~ x3
  f[4] = f4 ~ x4
  f[5] = f5 ~ x5
  f[6] = f6 ~ x6
  f[7] = f7 ~ x7
  f[8] = f8 ~ x8
  f[9] = f9 ~ x9
  f[10] = f10 ~ x10
end

-- Sets (f, g) to (g, f) if b == 1, (f, g) if b == 0.
-- (Presumably constant-time.)
local function fieldCswap(f, g, b)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)
  local g1, g2, g3, g4, g5, g6, g7, g8, g9, g10 = table.unpack(g, 1, 10)

  local x1 = f1 ~ g1
  local x2 = f2 ~ g2
  local x3 = f3 ~ g3
  local x4 = f4 ~ g4
  local x5 = f5 ~ g5
  local x6 = f6 ~ g6
  local x7 = f7 ~ g7
  local x8 = f8 ~ g8
  local x9 = f9 ~ g9
  local x10 = f10 ~ g10

  x1 = x1 & -b
  x2 = x2 & -b
  x3 = x3 & -b
  x4 = x4 & -b
  x5 = x5 & -b
  x6 = x6 & -b
  x7 = x7 & -b
  x8 = x8 & -b
  x9 = x9 & -b
  x10 = x10 & -b

  f[1] = f1 ~ x1
  f[2] = f2 ~ x2
  f[3] = f3 ~ x3
  f[4] = f4 ~ x4
  f[5] = f5 ~ x5
  f[6] = f6 ~ x6
  f[7] = f7 ~ x7
  f[8] = f8 ~ x8
  f[9] = f9 ~ x9
  f[10] = f10 ~ x10

  g[1] = g1 ~ x1
  g[2] = g2 ~ x2
  g[3] = g3 ~ x3
  g[4] = g4 ~ x4
  g[5] = g5 ~ x5
  g[6] = g6 ~ x6
  g[7] = g7 ~ x7
  g[8] = g8 ~ x8
  g[9] = g9 ~ x9
  g[10] = g10 ~ x10
end

local fieldReduce, fieldFromBytes

-- Returns `true` if `f` is congruent to zero.
local function fieldIsZero(f)
  local t = {}
  fieldReduce(t, f)
  local bits = 0

  for i = 1, #t, 1 do
    bits = bits | t[i]
  end

  return bits == 0
end

-- Returns `true` if `f` is "negative" (odd).
local function fieldIsNegative(f)
  local t = {}
  fieldReduce(t, f)

  -- select the least significant bit
  return t[1] & 1 == 1
end

-- Sets h to f * g.
local function fieldMul(h, f, g)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)
  local g1, g2, g3, g4, g5, g6, g7, g8, g9, g10 = table.unpack(g, 1, 10)

  local g2t19 = g2 * 19
  local g3t19 = g3 * 19
  local g4t19 = g4 * 19
  local g5t19 = g5 * 19
  local g6t19 = g6 * 19
  local g7t19 = g7 * 19
  local g8t19 = g8 * 19
  local g9t19 = g9 * 19
  local g10t19 = g10 * 19

  local f2t2 = f2 << 1
  local f4t2 = f4 << 1
  local f6t2 = f6 << 1
  local f8t2 = f8 << 1
  local f10t2 = f10 << 1

  local f1g1 = f1 * g1
  local f1g2 = f1 * g2
  local f1g3 = f1 * g3
  local f1g4 = f1 * g4
  local f1g5 = f1 * g5
  local f1g6 = f1 * g6
  local f1g7 = f1 * g7
  local f1g8 = f1 * g8
  local f1g9 = f1 * g9
  local f1g10 = f1 * g10

  local f2g1 = f2 * g1
  local f2g2t2 = f2t2 * g2
  local f2g3 = f2 * g3
  local f2g4t2 = f2t2 * g4
  local f2g5 = f2 * g5
  local f2g6t2 = f2t2 * g6
  local f2g7 = f2 * g7
  local f2g8t2 = f2t2 * g8
  local f2g9 = f2 * g9
  local f2g10t38 = f2t2 * g10t19

  local f3g1 = f3 * g1
  local f3g2 = f3 * g2
  local f3g3 = f3 * g3
  local f3g4 = f3 * g4
  local f3g5 = f3 * g5
  local f3g6 = f3 * g6
  local f3g7 = f3 * g7
  local f3g8 = f3 * g8
  local f3g9t19 = f3 * g9t19
  local f3g10t19 = f3 * g10t19

  local f4g1 = f4 * g1
  local f4g2t2 = f4t2 * g2
  local f4g3 = f4 * g3
  local f4g4t2 = f4t2 * g4
  local f4g5 = f4 * g5
  local f4g6t2 = f4t2 * g6
  local f4g7 = f4 * g7
  local f4g8t38 = f4t2 * g8t19
  local f4g9t19 = f4 * g9t19
  local f4g10t38 = f4t2 * g10t19

  local f5g1 = f5 * g1
  local f5g2 = f5 * g2
  local f5g3 = f5 * g3
  local f5g4 = f5 * g4
  local f5g5 = f5 * g5
  local f5g6 = f5 * g6
  local f5g7t19 = f5 * g7t19
  local f5g8t19 = f5 * g8t19
  local f5g9t19 = f5 * g9t19
  local f5g10t19 = f5 * g10t19

  local f6g1 = f6 * g1
  local f6g2t2 = f6t2 * g2
  local f6g3 = f6 * g3
  local f6g4t2 = f6t2 * g4
  local f6g5 = f6 * g5
  local f6g6t38 = f6t2 * g6t19
  local f6g7t19 = f6 * g7t19
  local f6g8t38 = f6t2 * g8t19
  local f6g9t19 = f6 * g9t19
  local f6g10t38 = f6t2 * g10t19

  local f7g1 = f7 * g1
  local f7g2 = f7 * g2
  local f7g3 = f7 * g3
  local f7g4 = f7 * g4
  local f7g5t19 = f7 * g5t19
  local f7g6t19 = f7 * g6t19
  local f7g7t19 = f7 * g7t19
  local f7g8t19 = f7 * g8t19
  local f7g9t19 = f7 * g9t19
  local f7g10t19 = f7 * g10t19

  local f8g1 = f8 * g1
  local f8g2t2 = f8t2 * g2
  local f8g3 = f8 * g3
  local f8g4t38 = f8t2 * g4t19
  local f8g5t19 = f8 * g5t19
  local f8g6t38 = f8t2 * g6t19
  local f8g7t19 = f8 * g7t19
  local f8g8t38 = f8t2 * g8t19
  local f8g9t19 = f8 * g9t19
  local f8g10t38 = f8t2 * g10t19

  local f9g1 = f9 * g1
  local f9g2 = f9 * g2
  local f9g3t19 = f9 * g3t19
  local f9g4t19 = f9 * g4t19
  local f9g5t19 = f9 * g5t19
  local f9g6t19 = f9 * g6t19
  local f9g7t19 = f9 * g7t19
  local f9g8t19 = f9 * g8t19
  local f9g9t19 = f9 * g9t19
  local f9g10t19 = f9 * g10t19

  local f10g1 = f10 * g1
  local f10g2t38 = f10t2 * g2t19
  local f10g3t19 = f10 * g3t19
  local f10g4t38 = f10t2 * g4t19
  local f10g5t19 = f10 * g5t19
  local f10g6t38 = f10t2 * g6t19
  local f10g7t19 = f10 * g7t19
  local f10g8t38 = f10t2 * g8t19
  local f10g9t19 = f10 * g9t19
  local f10g10t38 = f10t2 * g10t19

  local h1 = f1g1
    + f2g10t38 + f3g9t19 + f4g8t38 + f5g7t19 + f6g6t38
    + f7g5t19 + f8g4t38 + f9g3t19 + f10g2t38
  local h2 = f1g2 + f2g1
    + f3g10t19 + f4g9t19 + f5g8t19 + f6g7t19 + f7g6t19
    + f8g5t19 + f9g4t19 + f10g3t19
  local h3 = f1g3 + f2g2t2 + f3g1
    + f4g10t38 + f5g9t19 + f6g8t38 + f7g7t19 + f8g6t38 + f9g5t19 + f10g4t38
  local h4 = f1g4 + f2g3 + f3g2 + f4g1
    + f5g10t19 + f6g9t19 + f7g8t19 + f8g7t19 + f9g6t19 + f10g5t19
  local h5 = f1g5 + f2g4t2 + f3g3 + f4g2t2 + f5g1
    + f6g10t38 + f7g9t19 + f8g8t38 + f9g7t19 + f10g6t38
  local h6 = f1g6 + f2g5 + f3g4 + f4g3 + f5g2 + f6g1
    + f7g10t19 + f8g9t19 + f9g8t19 + f10g7t19
  local h7 = f1g7 + f2g6t2 + f3g5 + f4g4t2 + f5g3 + f6g2t2 + f7g1
    + f8g10t38 + f9g9t19 + f10g8t38
  local h8 = f1g8 + f2g7 + f3g6 + f4g5 + f5g4 + f6g3 + f7g2 + f8g1
    + f9g10t19 + f10g9t19
  local h9 =
    f1g9 + f2g8t2 + f3g7 + f4g6t2 + f5g5 + f6g4t2 + f7g3 + f8g2t2 + f9g1
    + f10g10t38
  local h10 =
    f1g10 + f2g9 + f3g8 + f4g7 + f5g6 + f6g5 + f7g4 + f8g3 + f9g2 + f10g1

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry2 = h2 + (1 << 24) >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry6 = h6 + (1 << 24) >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry3 = h3 + (1 << 25) >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry7 = h7 + (1 << 25) >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry4 = h4 + (1 << 24) >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry8 = h8 + (1 << 24) >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry9 = h9 + (1 << 25) >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 + (1 << 24) >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
end

-- Sets h to f * f.
local function fieldSq(h, f)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)

  local f1t2 = f1 << 1
  local f2t2 = f2 << 1
  local f3t2 = f3 << 1
  local f4t2 = f4 << 1
  local f5t2 = f5 << 1
  local f6t2 = f6 << 1
  local f7t2 = f7 << 1
  local f8t2 = f8 << 1

  local f6t38 = f6 * 38
  local f7t19 = f7 * 19
  local f8t38 = f8 * 38
  local f9t19 = f9 * 19
  local f10t38 = f10 * 38

  local f1f1 = f1 * f1
  local f1f2t2 = f1t2 * f2
  local f1f3t2 = f1t2 * f3
  local f1f4t2 = f1t2 * f4
  local f1f5t2 = f1t2 * f5
  local f1f6t2 = f1t2 * f6
  local f1f7t2 = f1t2 * f7
  local f1f8t2 = f1t2 * f8
  local f1f9t2 = f1t2 * f9
  local f1f10t2 = f1t2 * f10

  local f2f2t2 = f2t2 * f2
  local f2f3t2 = f2t2 * f3
  local f2f4t4 = f2t2 * f4t2
  local f2f5t2 = f2t2 * f5
  local f2f6t4 = f2t2 * f6t2
  local f2f7t2 = f2t2 * f7
  local f2f8t4 = f2t2 * f8t2
  local f2f9t2 = f2t2 * f9
  local f2f10t76 = f2t2 * f10t38

  local f3f3 = f3 * f3
  local f3f4t2 = f3t2 * f4
  local f3f5t2 = f3t2 * f5
  local f3f6t2 = f3t2 * f6
  local f3f7t2 = f3t2 * f7
  local f3f8t2 = f3t2 * f8
  local f3f9t38 = f3t2 * f9t19
  local f3f10t38 = f3 * f10t38

  local f4f4t2 = f4t2 * f4
  local f4f5t2 = f4t2 * f5
  local f4f6t4 = f4t2 * f6t2
  local f4f7t2 = f4t2 * f7
  local f4f8t76 = f4t2 * f8t38
  local f4f9t38 = f4t2 * f9t19
  local f4f10t76 = f4t2 * f10t38

  local f5f5 = f5 * f5
  local f5f6t2 = f5t2 * f6
  local f5f7t38 = f5t2 * f7t19
  local f5f8t38 = f5 * f8t38
  local f5f9t38 = f5t2 * f9t19
  local f5f10t38 = f5 * f10t38

  local f6f6t38 = f6 * f6t38
  local f6f7t38 = f6t2 * f7t19
  local f6f8t76 = f6t2 * f8t38
  local f6f9t38 = f6t2 * f9t19
  local f6f10t76 = f6t2 * f10t38

  local f7f7t19 = f7 * f7t19
  local f7f8t38 = f7 * f8t38
  local f7f9t38 = f7t2 * f9t19
  local f7f10t38 = f7 * f10t38

  local f8f8t38 = f8 * f8t38
  local f8f9t38 = f8t2 * f9t19
  local f8f10t76 = f8t2 * f10t38

  local f9f9t19 = f9 * f9t19
  local f9f10t38 = f9 * f10t38

  local f10f10t38 = f10 * f10t38

  local h1 = f1f1 + f2f10t76 + f3f9t38 + f4f8t76 + f5f7t38 + f6f6t38
  local h2 = f1f2t2 + f3f10t38 + f4f9t38 + f5f8t38 + f6f7t38
  local h3 = f1f3t2 + f2f2t2 + f4f10t76 + f5f9t38 + f6f8t76 + f7f7t19
  local h4 = f1f4t2 + f2f3t2 + f5f10t38 + f6f9t38 + f7f8t38
  local h5 = f1f5t2 + f2f4t4 + f3f3 + f6f10t76 + f7f9t38 + f8f8t38
  local h6 = f1f6t2 + f2f5t2 + f3f4t2 + f7f10t38 + f8f9t38
  local h7 = f1f7t2 + f2f6t4 + f3f5t2 + f4f4t2 + f8f10t76 + f9f9t19
  local h8 = f1f8t2 + f2f7t2 + f3f6t2 + f4f5t2 + f9f10t38
  local h9 = f1f9t2 + f2f8t4 + f3f7t2 + f4f6t4 + f5f5 + f10f10t38
  local h10 = f1f10t2 + f2f9t2 + f3f8t2 + f4f7t2 + f5f6t2

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry2 = h2 + (1 << 24) >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry6 = h6 + (1 << 24) >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry3 = h3 + (1 << 25) >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry7 = h7 + (1 << 25) >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry4 = h4 + (1 << 24) >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry8 = h8 + (1 << 24) >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry9 = h9 + (1 << 25) >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 + (1 << 24) >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
end

-- Sets h to 2 * f * f.
local function fieldSq2(h, f)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)

  local f1t2 = f1 << 1
  local f2t2 = f2 << 1
  local f3t2 = f3 << 1
  local f4t2 = f4 << 1
  local f5t2 = f5 << 1
  local f6t2 = f6 << 1
  local f7t2 = f7 << 1
  local f8t2 = f8 << 1

  local f6t38 = f6 * 38
  local f7t19 = f7 * 19
  local f8t38 = f8 * 38
  local f9t19 = f9 * 19
  local f10t38 = f10 * 38

  local f1f1 = f1 * f1
  local f1f2t2 = f1t2 * f2
  local f1f3t2 = f1t2 * f3
  local f1f4t2 = f1t2 * f4
  local f1f5t2 = f1t2 * f5
  local f1f6t2 = f1t2 * f6
  local f1f7t2 = f1t2 * f7
  local f1f8t2 = f1t2 * f8
  local f1f9t2 = f1t2 * f9
  local f1f10t2 = f1t2 * f10

  local f2f2t2 = f2t2 * f2
  local f2f3t2 = f2t2 * f3
  local f2f4t4 = f2t2 * f4t2
  local f2f5t2 = f2t2 * f5
  local f2f6t4 = f2t2 * f6t2
  local f2f7t2 = f2t2 * f7
  local f2f8t4 = f2t2 * f8t2
  local f2f9t2 = f2t2 * f9
  local f2f10t76 = f2t2 * f10t38

  local f3f3 = f3 * f3
  local f3f4t2 = f3t2 * f4
  local f3f5t2 = f3t2 * f5
  local f3f6t2 = f3t2 * f6
  local f3f7t2 = f3t2 * f7
  local f3f8t2 = f3t2 * f8
  local f3f9t38 = f3t2 * f9t19
  local f3f10t38 = f3 * f10t38

  local f4f4t2 = f4t2 * f4
  local f4f5t2 = f4t2 * f5
  local f4f6t4 = f4t2 * f6t2
  local f4f7t2 = f4t2 * f7
  local f4f8t76 = f4t2 * f8t38
  local f4f9t38 = f4t2 * f9t19
  local f4f10t76 = f4t2 * f10t38

  local f5f5 = f5 * f5
  local f5f6t2 = f5t2 * f6
  local f5f7t38 = f5t2 * f7t19
  local f5f8t38 = f5 * f8t38
  local f5f9t38 = f5t2 * f9t19
  local f5f10t38 = f5 * f10t38

  local f6f6t38 = f6 * f6t38
  local f6f7t38 = f6t2 * f7t19
  local f6f8t76 = f6t2 * f8t38
  local f6f9t38 = f6t2 * f9t19
  local f6f10t76 = f6t2 * f10t38

  local f7f7t19 = f7 * f7t19
  local f7f8t38 = f7 * f8t38
  local f7f9t38 = f7t2 * f9t19
  local f7f10t38 = f7 * f10t38

  local f8f8t38 = f8 * f8t38
  local f8f9t38 = f8t2 * f9t19
  local f8f10t76 = f8t2 * f10t38

  local f9f9t19 = f9 * f9t19
  local f9f10t38 = f9 * f10t38

  local f10f10t38 = f10 * f10t38

  local h1 = f1f1 + f2f10t76 + f3f9t38 + f4f8t76 + f5f7t38 + f6f6t38
  local h2 = f1f2t2 + f3f10t38 + f4f9t38 + f5f8t38 + f6f7t38
  local h3 = f1f3t2 + f2f2t2 + f4f10t76 + f5f9t38 + f6f8t76 + f7f7t19
  local h4 = f1f4t2 + f2f3t2 + f5f10t38 + f6f9t38 + f7f8t38
  local h5 = f1f5t2 + f2f4t4 + f3f3 + f6f10t76 + f7f9t38 + f8f8t38
  local h6 = f1f6t2 + f2f5t2 + f3f4t2 + f7f10t38 + f8f9t38
  local h7 = f1f7t2 + f2f6t4 + f3f5t2 + f4f4t2 + f8f10t76 + f9f9t19
  local h8 = f1f8t2 + f2f7t2 + f3f6t2 + f4f5t2 + f9f10t38
  local h9 = f1f9t2 + f2f8t4 + f3f7t2 + f4f6t4 + f5f5 + f10f10t38
  local h10 = f1f10t2 + f2f9t2 + f3f8t2 + f4f7t2 + f5f6t2

  h1 = h1 << 1
  h2 = h2 << 1
  h3 = h3 << 1
  h4 = h4 << 1
  h5 = h5 << 1
  h6 = h6 << 1
  h7 = h7 << 1
  h8 = h8 << 1
  h9 = h9 << 1
  h10 = h10 << 1

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry2 = h2 + (1 << 24) >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry6 = h6 + (1 << 24) >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry3 = h3 + (1 << 25) >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry7 = h7 + (1 << 25) >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry4 = h4 + (1 << 24) >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry8 = h8 + (1 << 24) >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry9 = h9 + (1 << 25) >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 + (1 << 24) >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
end
-- Sets h to f * n, where n is a 32-bit integer.
local function fieldMul32(h, f, n)
  local f1, f2, f3, f4, f5, f6, f7, f8, f9, f10 = table.unpack(f, 1, 10)

  local h1 = f1 * n
  local h2 = f2 * n
  local h3 = f3 * n
  local h4 = f4 * n
  local h5 = f5 * n
  local h6 = f6 * n
  local h7 = f7 * n
  local h8 = f8 * n
  local h9 = f9 * n
  local h10 = f10 * n

  local carry10 = h10 + (1 << 24) >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry2 = h2 + (1 << 24) >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry4 = h4 + (1 << 24) >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry6 = h6 + (1 << 24) >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry8 = h8 + (1 << 24) >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry3 = h3 + (1 << 25) >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry7 = h7 + (1 << 25) >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry9 = h9 + (1 << 25) >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
end

-- File: src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c.

-- Sets h to z^-1.
--
-- If z is zero, sets h to zero.
local function fieldInvert(h, z)
  local t1, t2, t3, t4 = {}, {}, {}, {}

  fieldSq(t1, z) -- t1 = z^2
  fieldSq(t2, t1) -- t2 = z^4
  fieldSq(t2, t2) -- t2 = z^8
  fieldMul(t2, z, t2) -- t2 = z^9
  fieldMul(t1, t1, t2) -- t1 = z^11
  fieldSq(t3, t1) -- t3 = z^22
  fieldMul(t2, t2, t3) -- t2 = z^31
  fieldSq(t3, t2) -- t3 = z^62

  for i = 1, 4, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^992

  fieldMul(t2, t3, t2) -- t2 = z^0x3ff
  fieldSq(t3, t2) -- t3 = z^0x7f3

  for i = 1, 9, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0xffc00

  fieldMul(t3, t3, t2) -- t3 = z^0xfffff
  fieldSq(t4, t3) -- t4 = z^0x1ffffe

  for i = 1, 19, 1 do
    fieldSq(t4, t4)
  end
  -- t4 = z^0xfffff00000

  fieldMul(t3, t4, t3) -- t3 = z^0xffffffffff

  for i = 1, 10, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0x3fffffffffc00

  fieldMul(t2, t3, t2) -- t2 = z^0x3ffffffffffff
  fieldSq(t3, t2) -- t3 = z^0x7fffffffffffe

  for i = 1, 49, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0xffffffffffffc000000000000

  fieldMul(t3, t3, t2) -- t3 = z^0xfffffffffffffffffffffffff
  fieldSq(t4, t3) -- t4 = z^0x1ffffffffffffffffffffffffe

  for i = 1, 99, 1 do
    fieldSq(t4, t4)
  end
  -- t4 = z^0xfffffffffffffffffffffffff0000000000000000000000000

  fieldMul(t3, t4, t3)
  -- t3 = z^0xffffffffffffffffffffffffffffffffffffffffffffffffff

  for i = 1, 50, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0x3fffffffffffffffffffffffffffffffffffffffffffffffffc000000000000

  fieldMul(t2, t3, t2)
  -- t2 = z^0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

  for i = 1, 5, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe0
  --    = z^(2^255 - 32)

  fieldMul(h, t2, t1) -- h = z^(2^255 - 21) = z^(p - 2)
end

-- Sets h to z^(2^252 - 3).
local function fieldPow2p252m3(h, z)
  local t1, t2, t3 = {}, {}, {}

  fieldSq(t1, z) -- t1 = z^2
  fieldSq(t2, t1) -- t2 = z^4
  fieldSq(t2, t2) -- t2 = z^8
  fieldMul(t2, z, t2) -- t2 = z^9
  fieldMul(t1, t1, t2) -- t1 = z^11
  fieldSq(t1, t1) -- t1 = z^22
  fieldMul(t1, t2, t1) -- t1 = z^31
  fieldSq(t2, t1) -- t2 = z^62

  for i = 1, 4, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^992

  fieldMul(t1, t2, t1) -- t1 = z^0x3ff
  fieldSq(t2, t1) -- t2 = z^0x7fe

  for i = 1, 9, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^0xffc00

  fieldMul(t2, t2, t1) -- t2 = z^0xfffff
  fieldSq(t3, t2) -- t3 = z^0x1ffffe

  for i = 1, 19, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0xfffff00000

  fieldMul(t2, t3, t2) -- t2 = z^0xffffffffff

  for i = 1, 10, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^0x3fffffffffc00

  fieldMul(t1, t2, t1) -- t1 = z^0x3ffffffffffff
  fieldSq(t2, t1) -- t2 = z^0x7fffffffffffe

  for i = 1, 49, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^0xffffffffffffc000000000000

  fieldMul(t2, t2, t1) -- t2 = z^0xfffffffffffffffffffffffff
  fieldSq(t3, t2) -- t3 = z^0x1ffffffffffffffffffffffffe

  for i = 1, 99, 1 do
    fieldSq(t3, t3)
  end
  -- t3 = z^0xfffffffffffffffffffffffff0000000000000000000000000

  fieldMul(t2, t3, t2)
  -- t2 = z^0xffffffffffffffffffffffffffffffffffffffffffffffffff

  for i = 1, 50, 1 do
    fieldSq(t2, t2)
  end
  -- t2 = z^0x3fffffffffffffffffffffffffffffffffffffffffffffffffc000000000000

  fieldMul(t1, t2, t1)
  -- t1 = z^0x3ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
  fieldSq(t1, t1)
  -- t1 = z^0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
  fieldSq(t1, t1)
  -- t1 = z^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffc
  fieldMul(h, t1, z)
  -- h = z^0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd
  --   = z^(2^252 - 3)
end

-- Sets h to f if b == 0, or -f if b == 1.
local function fieldCeg(h, f, b)
  local mf = {}
  fieldNeg(mf, f)
  fieldCopy(h, f)
  fieldCmov(h, mf, b)
end

-- Sets x to the square root of x2.
--
-- If x2 is not a square in GF(2²⁵⁵ - 19), puts garbage into x.
local function fieldSqrtUnchecked(x, x2)
  local posRoot, negRoot, negRootSq, e = {}, {}, {}, {}

  fieldPow2p252m3(e, x2)
  fieldMul(posRoot, e, x2)
  fieldMul(negRoot, posRoot, fieldSqrtm1)
  fieldSq(negRootSq, negRoot)
  fieldSub(e, x2, negRootSq)
  fieldCopy(x, posRoot)
  fieldCmov(x, negRoot, fieldIsZero(e) and 1 or 0)
end

-- Sets x to the square root of x2.
--
-- If x2 is not a square in GF(2²⁵⁵ - 19), returns `false`.
local function fieldSqrt(x, x2)
  fieldSqrtUnchecked(x, x2)

  local actualSq = {}
  fieldSq(actualSq, x)
  fieldSub(actualSq, actualSq, x2)

  return fieldIsZero(actualSq)
end

-- As far as I understand, this precomputes a sequence of operations for
-- double-and-add scalar point multiplication.
local function getSlide(a)
  local r = {}
  local words = {("<I8I8I8I8"):unpack(a)}
  words[5] = nil

  for i = 0, 255, 1 do
    r[i + 1] = words[1 + (i >> 6)] >> (i & 0x3f) & 0x1
  end

  for i = 1, 256, 1 do
    if r[i] == 1 then
      for b = 1, 6, 1 do
        if i + b <= 256 and r[i + b] == 1 then
          local ribs = r[i + b] << b
          local cmp = r[i] + ribs

          if cmp <= 15 then
            r[i] = cmp
            r[i + b] = 0
          else
            cmp = r[i] - ribs

            if cmp < -15 then
              break
            end

            r[i] = cmp

            for k = i + b, 256, 1 do
              if r[k] == 0 then
                r[k] = 1
                break
              end

              r[k] = 0
            end
          end
        end
      end
    end
  end

  return r
end

local function groupProj2Zero(h)
  h = h or {}
  h[1] = field0()
  h[2] = field1()
  h[3] = field1()
  h[4] = field1()

  return h
end

local function groupProjZero(h)
  h = h or {}
  h[1] = field0()
  h[2] = field1()
  h[3] = field1()

  return h
end

local function groupExtendedZero(h)
  h = h or {}
  h[1] = field0()
  h[2] = field1()
  h[3] = field1()
  h[4] = field0()

  return h
end

local function groupCachedZero(h)
  h = h or {}

  h.ypx = field1()
  h.ymx = field1()
  h.z = field1()
  h.t2d = field0()

  return h
end

-- Given a EC point p, expressed in extended coordinates, produces cached
-- values (ypx = y + x, ymx = y - x, t2d = t * 2d) in projective coordinates.
local function groupExtendedToCached(p)
  local ypx, ymx, t2d = {}, {}, {}
  fieldAdd(ypx, p[2], p[1])
  fieldSub(ymx, p[2], p[1])
  fieldMul(t2d, p[4], ed25519d2)

  return {
    ypx = ypx,
    ymx = ymx,
    z = util.copy(p[3]),
    t2d = t2d,
  }
end

-- Sets r, in extended coordinates, to p, in per-coordinate projective
-- representation.
local function groupProj2ToExtended(r, p)
  fieldMul(r[1], p[1], p[4])
  fieldMul(r[2], p[2], p[3])
  fieldMul(r[3], p[3], p[4])
  fieldMul(r[4], p[1], p[2])
end

-- Sets r, in projective coordinates, to p, in per-coordinate projective
-- representation.
local function groupProj2ToProj(r, p)
  fieldMul(r[1], p[1], p[4])
  fieldMul(r[2], p[2], p[3])
  fieldMul(r[3], p[3], p[4])
end

-- Sets r, in extended coordinates, to p, in projective coordinates.
local function groupProjToExtended(r, p)
  fieldCopy(r[1], p[1])
  fieldCopy(r[2], p[2])
  fieldCopy(r[3], p[3])
  fieldMul(r[4], p[1], p[2])
end

-- Sets r to 2 * p.
--
-- r is an EC point in per-coordinate projective representation.
-- p is an EC point in projective coordinates.
local function groupProjDouble(r, p)
  local t1 = {}

  fieldSq(r[1], p[1])
  fieldSq(r[3], p[2])
  fieldSq2(r[4], p[3])
  fieldAdd(r[2], p[1], p[2])
  fieldSq(t1, r[2])
  fieldAdd(r[2], r[3], r[1])
  fieldSub(r[3], r[3], r[1])
  fieldSub(r[1], t1, r[2])
  fieldSub(r[4], r[4], r[3])
end

-- Sets r to 2 * p.
--
-- r is an EC point in per-coordinate projective representation.
-- p is an EC point in extended coordinates.
local function groupExtendedDouble(r, p)
  return groupProjDouble(r, p)
end

-- Sets r to p + q.
--
-- r is an EC point in per-coordinate projective representation.
-- p is an EC point in extended coordinates.
-- q stores cached values (see groupExtendedToCached) for an EC point.
local function groupAddCached(r, p, q)
  local t1 = {}

  fieldAdd(r[1], p[2], p[1])
  fieldSub(r[2], p[2], p[1])
  fieldMul(r[3], r[1], q.ypx)
  fieldMul(r[2], r[2], q.ymx)
  fieldMul(r[4], q.t2d, p[4])
  fieldMul(r[1], p[3], q.z)
  fieldAdd(t1, r[1], r[1])
  fieldSub(r[1], r[3], r[2])
  fieldAdd(r[2], r[3], r[2])
  fieldAdd(r[3], t1, r[4])
  fieldSub(r[4], t1, r[4])
end

-- Sets r to p - q.
--
-- r is an EC point in per-coordinate projective representation.
-- p is an EC point in extended coordinates.
-- q stores cached values (see groupExtendedToCached) for an EC point.
local function groupSubCached(r, p, q)
  local t1 = {}

  fieldAdd(r[1], p[2], p[1])
  fieldSub(r[2], p[2], p[1])
  fieldMul(r[3], r[1], q.ymx)
  fieldMul(r[2], r[2], q.ypx)
  fieldMul(r[4], q.t2d, p[4])
  fieldMul(r[1], p[3], q.z)
  fieldAdd(t1, r[1], r[1])
  fieldSub(r[1], r[3], r[2])
  fieldAdd(r[2], r[3], r[2])
  fieldSub(r[3], t1, r[4])
  fieldAdd(r[4], t1, r[4])
end

-- Sets r to p + q.
--
-- r in an EC point in per-coordinate projective representation.
-- p is an EC point in extended coordinates.
-- q stores precomputed values for an EC points.
local function groupAddPrecomp(r, p, q)
  local t1 = {}

  fieldAdd(r[1], p[2], p[1])
  fieldSub(r[2], p[2], p[1])
  fieldMul(r[3], r[1], q.ypx)
  fieldMul(r[2], r[2], q.ymx)
  fieldMul(r[4], q.xy2d, p[4])
  fieldAdd(t1, p[3], p[3])
  fieldSub(r[1], r[3], r[2])
  fieldAdd(r[2], r[3], r[2])
  fieldAdd(r[3], t1, r[4])
  fieldSub(r[4], t1, r[4])
end

-- Sets r to p + q.
--
-- r in an EC point in per-coordinate projective representation.
-- p is an EC point in extended coordinates.
-- q stores precomputed values for an EC points.
local function groupSubPrecomp(r, p, q)
  local t1 = {}

  fieldAdd(r[1], p[2], p[1])
  fieldSub(r[2], p[2], p[1])
  fieldMul(r[3], r[1], q.ymx)
  fieldMul(r[2], r[2], q.ypx)
  fieldMul(r[4], q.xy2d, p[4])
  fieldAdd(t1, p[3], p[3])
  fieldSub(r[1], r[3], r[2])
  fieldAdd(r[2], r[3], r[2])
  fieldSub(r[3], t1, r[4])
  fieldAdd(r[4], t1, r[4])
end

-- Sets r to -p.
--
-- All points are in extended coordinates.
local function groupExtendedNeg(r, p)
  fieldNeg(r[1], p[1])
  fieldCopy(r[2], p[2])
  fieldCopy(r[3], p[3])
  fieldNeg(r[4], p[4])
end

-- Sets r to p + q.
--
-- All points are in extended coordinates.
local function groupExtendedAdd(r, p, q)
  local rProj2 = groupProj2Zero()

  groupAddCached(rProj2, p, groupExtendedToCached(q))
  groupProj2ToExtended(r, rProj2)
end

-- Sets r to p - q.
--
-- All points are in extended coordinates.
local function groupExtendedSub(r, p, q)
  local negQ = groupExtendedZero()
  groupExtendedNeg(negQ, q)
  groupExtendedAdd(r, p, negQ)
end

-- Sets r to a * pa + b * B.
--
-- pa is a curve point in extended coordinates. B is the Ed25519 base point.
-- a and b are scalars, represented as 32-byte strings.
-- r is represented in projective coordinates.
local function groupDoubleScalarMul(r, a, pa, b)
  local t = groupProj2Zero()
  local u = groupExtendedZero()
  local pa2 = groupExtendedZero()

  local aslide = getSlide(a)
  local bslide = getSlide(b)
  local ai = {groupExtendedToCached(pa)}

  groupExtendedDouble(t, pa)
  groupProj2ToExtended(pa2, t)

  groupAddCached(t, pa2, ai[1])
  groupProj2ToExtended(u, t)
  ai[2] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[2])
  groupProj2ToExtended(u, t)
  ai[3] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[3])
  groupProj2ToExtended(u, t)
  ai[4] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[4])
  groupProj2ToExtended(u, t)
  ai[5] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[5])
  groupProj2ToExtended(u, t)
  ai[6] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[6])
  groupProj2ToExtended(u, t)
  ai[7] = groupExtendedToCached(u)

  groupAddCached(t, pa2, ai[7])
  groupProj2ToExtended(u, t)
  ai[8] = groupExtendedToCached(u)

  groupProjZero(r)

  local i = 256

  repeat
    if aslide[i] ~= 0 or bslide[i] ~= 0 then
      break
    end

    i = i - 1
  until i == 0

  for i = i, 1, -1 do
    groupProjDouble(t, r)

    if aslide[i] > 0 then
      groupProj2ToExtended(u, t)
      groupAddCached(t, u, ai[1 + (aslide[i] >> 1)])
    elseif aslide[i] < 0 then
      groupProj2ToExtended(u, t)
      groupSubCached(t, u, ai[1 + (-aslide[i] >> 1)])
    end

    if bslide[i] > 0 then
      groupProj2ToExtended(u, t)
      groupAddPrecomp(t, u, constBi[1 + (bslide[i] >> 1)])
    elseif bslide[i] < 0 then
      groupProj2ToExtended(u, t)
      groupSubPrecomp(t, u, constBi[1 + (-bslide[i] >> 1)])
    end

    groupProj2ToProj(r, t)
  end
end

-- Returns `true` iff s, as a 32-byte integer, is less than p.
local function groupIsCanonical(s)
  assert(#s == 32)

  local c = s:byte(32) & 0x7f ~ 0x7f

  for i = 31, 2, -1 do
    c = c | s:byte(i) ~ 0xff
  end

  c = c - 1 >> 8
  local d = 0xed - 1 - s:byte(1) >> 8

  return c & d & 1 == 0
end

-- Sets h to the EC point encoded as s.
--
-- The most significant bit is used to select the right x value.
local function groupFromBytesWithSign(h, s)
  assert(#s == 32)

  local u, v, v3, vxx, mRootCheck, pRootCheck = {}, {}, {}, {}, {}, {}

  h[2] = fieldFromBytes(s)
  field1(h[3])
  fieldSq(u, h[2])
  fieldMul(v, u, ed25519d)
  fieldSub(u, u, h[3])
  fieldAdd(v, v, h[3])

  fieldSq(v3, v)
  fieldMul(v3, v3, v)
  fieldSq(h[1], v3)
  fieldMul(h[1], h[1], v)
  fieldMul(h[1], h[1], u)

  fieldPow2p252m3(h[1], h[1])
  fieldMul(h[1], h[1], v3)
  fieldMul(h[1], h[1], u)

  fieldSq(vxx, h[1])
  fieldMul(vxx, vxx, v)
  fieldSub(mRootCheck, vxx, u)

  if not fieldIsZero(mRootCheck) then
    fieldAdd(pRootCheck, vxx, u)

    if not fieldIsZero(pRootCheck) then
      return false
    end

    fieldMul(h[1], h[1], fieldSqrtm1)
  end

  if fieldIsNegative(h[1]) == (s:byte(32) >> 7 == 1) then
    fieldNeg(h[1], h[1])
  end

  fieldMul(h[4], h[1], h[2])

  return true
end

-- Sets h to the EC points encoded as s.
local function groupFromBytes(h, s)
  local u, v, vxx, mRootCheck, pRootCheck, negX, xtsqrtm1 =
    {}, {}, {}, {}, {}, {}, {}

  h[2] = fieldFromBytes(s)
  field1(h[3])
  fieldSq(u, h[2])
  fieldMul(v, u, ed25519d)
  fieldSub(u, u, h[3])
  fieldAdd(v, v, h[3])

  fieldMul(h[1], u, v)
  fieldPow2p252m3(h[1], h[1])
  fieldMul(h[1], u, h[1])

  fieldSq(vxx, h[1])
  fieldMul(vxx, vxx, v)
  fieldSub(mRootCheck, vxx, u)
  fieldAdd(pRootCheck, vxx, u)

  local hasMRoot = fieldIsZero(mRootCheck)
  local hasPRoot = fieldIsZero(pRootCheck)

  fieldMul(xtsqrtm1, h[1], fieldSqrtm1)
  fieldCmov(h[1], xtsqrtm1, hasMRoot and 0 or 1)

  fieldNeg(negX, h[1])
  fieldCmov(
    h[1],
    negX,
    fieldIsNegative(h[1]) ~= (s:byte(32) >> 7 == 1) and 1 or 0
  )
  fieldMul(h[4], h[1], h[2])

  return hasMRoot or hasPRoot
end

-- p is in extended coordinates.
local function groupHasSmallOrder(p)
  local ret = 0

  local recip = {}
  fieldInvert(recip, p[3])

  local x = {}
  fieldMul(x, p[1], recip)
  ret = ret | (fieldIsZero(x) and 1 or 0)

  local y = {}
  fieldMul(y, p[2], recip)
  ret = ret | (fieldIsZero(y) and 1 or 0)

  local negX = {}
  fieldNeg(negX, p[1])

  local ytsqrtm1 = {}
  fieldMul(ytsqrtm1, y, fieldSqrtm1)

  local c = {}
  fieldSub(c, ytsqrtm1, x)
  ret = ret | (fieldIsZero(c) and 1 or 0)

  fieldSub(c, ytsqrtm1, negX)
  ret = ret | (fieldIsZero(c) and 1 or 0)

  return ret ~= 0
end

local function scalarIsCanonical(s)
  assert(#s == 32)

  local c = 0
  local n = 1

  for i = 32, 1, -1 do
    local si = s:byte(i)
    local li = l:byte(i)
    c = c | si - li >> 8 & n
    n = n & (si ~ li) - 1 >> 8
  end

  return c ~= 0
end

-- Reduces s, a 64-byte little-endian integer, modulo L, the order of the
-- elliptic curve group.
--
-- Returns a 32-byte string.
local function scalarReduce(s)
  assert(#s == 64)

  local s1 = 0x1fffff & ("<I3"):unpack(s, 1)
  local s2 = 0x1fffff & ("<I4"):unpack(s, 3) >> 5
  local s3 = 0x1fffff & ("<I3"):unpack(s, 6) >> 2
  local s4 = 0x1fffff & ("<I4"):unpack(s, 8) >> 7
  local s5 = 0x1fffff & ("<I4"):unpack(s, 11) >> 4
  local s6 = 0x1fffff & ("<I3"):unpack(s, 14) >> 1
  local s7 = 0x1fffff & ("<I4"):unpack(s, 16) >> 6
  local s8 = 0x1fffff & ("<I3"):unpack(s, 19) >> 3
  local s9 = 0x1fffff & ("<I3"):unpack(s, 22)
  local s10 = 0x1fffff & ("<I4"):unpack(s, 24) >> 5
  local s11 = 0x1fffff & ("<I3"):unpack(s, 27) >> 2
  local s12 = 0x1fffff & ("<I4"):unpack(s, 29) >> 7
  local s13 = 0x1fffff & ("<I4"):unpack(s, 32) >> 4
  local s14 = 0x1fffff & ("<I3"):unpack(s, 35) >> 1
  local s15 = 0x1fffff & ("<I4"):unpack(s, 37) >> 6
  local s16 = 0x1fffff & ("<I3"):unpack(s, 40) >> 3
  local s17 = 0x1fffff & ("<I3"):unpack(s, 43)
  local s18 = 0x1fffff & ("<I4"):unpack(s, 45) >> 5
  local s19 = 0x1fffff & ("<I3"):unpack(s, 48) >> 2
  local s20 = 0x1fffff & ("<I4"):unpack(s, 50) >> 7
  local s21 = 0x1fffff & ("<I4"):unpack(s, 53) >> 4
  local s22 = 0x1fffff & ("<I3"):unpack(s, 56) >> 1
  local s23 = 0x1fffff & ("<I4"):unpack(s, 58) >> 6
  local s24 = ("<I4"):unpack(s, 61) >> 3

  s12 = s12 + s24 * 666643
  s13 = s13 + s24 * 470296
  s14 = s14 + s24 * 654183
  s15 = s15 - s24 * 997805
  s16 = s16 + s24 * 136657
  s17 = s17 - s24 * 683901

  s11 = s11 + s23 * 666643
  s12 = s12 + s23 * 470296
  s13 = s13 + s23 * 654183
  s14 = s14 - s23 * 997805
  s15 = s15 + s23 * 136657
  s16 = s16 - s23 * 683901

  s10 = s10 + s22 * 666643
  s11 = s11 + s22 * 470296
  s12 = s12 + s22 * 654183
  s13 = s13 - s22 * 997805
  s14 = s14 + s22 * 136657
  s15 = s15 - s22 * 683901

  s9 = s9 + s21 * 666643
  s10 = s10 + s21 * 470296
  s11 = s11 + s21 * 654183
  s12 = s12 - s21 * 997805
  s13 = s13 + s21 * 136657
  s14 = s14 - s21 * 683901

  s8 = s8 + s20 * 666643
  s9 = s9 + s20 * 470296
  s10 = s10 + s20 * 654183
  s11 = s11 - s20 * 997805
  s12 = s12 + s20 * 136657
  s13 = s13 - s20 * 683901

  s7 = s7 + s19 * 666643
  s8 = s8 + s19 * 470296
  s9 = s9 + s19 * 654183
  s10 = s10 - s19 * 997805
  s11 = s11 + s19 * 136657
  s12 = s12 - s19 * 683901

  local carry7 = s7 + (1 << 20) >> 21
  carry7 = carry7 | -(carry7 & 1 << 63 >> 21)
  s8 = s8 + carry7
  s7 = s7 - (carry7 << 21)

  local carry9 = s9 + (1 << 20) >> 21
  carry9 = carry9 | -(carry9 & 1 << 63 >> 21)
  s10 = s10 + carry9
  s9 = s9 - (carry9 << 21)

  local carry11 = s11 + (1 << 20) >> 21
  carry11 = carry11 | -(carry11 & 1 << 63 >> 21)
  s12 = s12 + carry11
  s11 = s11 - (carry11 << 21)

  local carry13 = s13 + (1 << 20) >> 21
  carry13 = carry13 | -(carry13 & 1 << 63 >> 21)
  s14 = s14 + carry13
  s13 = s13 - (carry13 << 21)

  local carry15 = s15 + (1 << 20) >> 21
  carry15 = carry15 | -(carry15 & 1 << 63 >> 21)
  s16 = s16 + carry15
  s15 = s15 - (carry15 << 21)

  local carry17 = s17 + (1 << 20) >> 21
  carry17 = carry17 | -(carry17 & 1 << 63 >> 21)
  s18 = s18 + carry17
  s17 = s17 - (carry17 << 21)

  local carry8 = s8 + (1 << 20) >> 21
  carry8 = carry8 | -(carry8 & 1 << 63 >> 21)
  s9 = s9 + carry8
  s8 = s8 - (carry8 << 21)

  local carry10 = s10 + (1 << 20) >> 21
  carry10 = carry10 | -(carry10 & 1 << 63 >> 21)
  s11 = s11 + carry10
  s10 = s10 - (carry10 << 21)

  local carry12 = s12 + (1 << 20) >> 21
  carry12 = carry12 | -(carry12 & 1 << 63 >> 21)
  s13 = s13 + carry12
  s12 = s12 - (carry12 << 21)

  local carry14 = s14 + (1 << 20) >> 21
  carry14 = carry14 | -(carry14 & 1 << 63 >> 21)
  s15 = s15 + carry14
  s14 = s14 - (carry14 << 21)

  local carry16 = s16 + (1 << 20) >> 21
  carry16 = carry16 | -(carry16 & 1 << 63 >> 21)
  s17 = s17 + carry16
  s16 = s16 - (carry16 << 21)

  s6 = s6 + s18 * 666643
  s7 = s7 + s18 * 470296
  s8 = s8 + s18 * 654183
  s9 = s9 - s18 * 997805
  s10 = s10 + s18 * 136657
  s11 = s11 - s18 * 683901

  s5 = s5 + s17 * 666643
  s6 = s6 + s17 * 470296
  s7 = s7 + s17 * 654183
  s8 = s8 - s17 * 997805
  s9 = s9 + s17 * 136657
  s10 = s10 - s17 * 683901

  s4 = s4 + s16 * 666643
  s5 = s5 + s16 * 470296
  s6 = s6 + s16 * 654183
  s7 = s7 - s16 * 997805
  s8 = s8 + s16 * 136657
  s9 = s9 - s16 * 683901

  s3 = s3 + s15 * 666643
  s4 = s4 + s15 * 470296
  s5 = s5 + s15 * 654183
  s6 = s6 - s15 * 997805
  s7 = s7 + s15 * 136657
  s8 = s8 - s15 * 683901

  s2 = s2 + s14 * 666643
  s3 = s3 + s14 * 470296
  s4 = s4 + s14 * 654183
  s5 = s5 - s14 * 997805
  s6 = s6 + s14 * 136657
  s7 = s7 - s14 * 683901

  s1 = s1 + s13 * 666643
  s2 = s2 + s13 * 470296
  s3 = s3 + s13 * 654183
  s4 = s4 - s13 * 997805
  s5 = s5 + s13 * 136657
  s6 = s6 - s13 * 683901

  s13 = 0

  local carry1 = s1 + (1 << 20) >> 21
  carry1 = carry1 | -(carry1 & 1 << 63 >> 21)
  s2 = s2 + carry1
  s1 = s1 - (carry1 << 21)

  local carry3 = s3 + (1 << 20) >> 21
  carry3 = carry3 | -(carry3 & 1 << 63 >> 21)
  s4 = s4 + carry3
  s3 = s3 - (carry3 << 21)

  local carry5 = s5 + (1 << 20) >> 21
  carry5 = carry5 | -(carry5 & 1 << 63 >> 21)
  s6 = s6 + carry5
  s5 = s5 - (carry5 << 21)

  local carry7 = s7 + (1 << 20) >> 21
  carry7 = carry7 | -(carry7 & 1 << 63 >> 21)
  s8 = s8 + carry7
  s7 = s7 - (carry7 << 21)

  local carry9 = s9 + (1 << 20) >> 21
  carry9 = carry9 | -(carry9 & 1 << 63 >> 21)
  s10 = s10 + carry9
  s9 = s9 - (carry9 << 21)

  local carry11 = s11 + (1 << 20) >> 21
  carry11 = carry11 | -(carry11 & 1 << 63 >> 21)
  s12 = s12 + carry11
  s11 = s11 - (carry11 << 21)

  local carry2 = s2 + (1 << 20) >> 21
  carry2 = carry2 | -(carry2 & 1 << 63 >> 21)
  s3 = s3 + carry2
  s2 = s2 - (carry2 << 21)

  local carry4 = s4 + (1 << 20) >> 21
  carry4 = carry4 | -(carry4 & 1 << 63 >> 21)
  s5 = s5 + carry4
  s4 = s4 - (carry4 << 21)

  local carry6 = s6 + (1 << 20) >> 21
  carry6 = carry6 | -(carry6 & 1 << 63 >> 21)
  s7 = s7 + carry6
  s6 = s6 - (carry6 << 21)

  local carry8 = s8 + (1 << 20) >> 21
  carry8 = carry8 | -(carry8 & 1 << 63 >> 21)
  s9 = s9 + carry8
  s8 = s8 - (carry8 << 21)

  local carry10 = s10 + (1 << 20) >> 21
  carry10 = carry10 | -(carry10 & 1 << 63 >> 21)
  s11 = s11 + carry10
  s10 = s10 - (carry10 << 21)

  local carry12 = s12 + (1 << 20) >> 21
  carry12 = carry12 | -(carry12 & 1 << 63 >> 21)
  s13 = s13 + carry12
  s12 = s12 - (carry12 << 21)

  s1 = s1 + s13 * 666643
  s2 = s2 + s13 * 470296
  s3 = s3 + s13 * 654183
  s4 = s4 - s13 * 997805
  s5 = s5 + s13 * 136657
  s6 = s6 - s13 * 683901
  s13 = 0

  local carry1 = s1 >> 21
  carry1 = carry1 | -(carry1 & 1 << 63 >> 21)
  s2 = s2 + carry1
  s1 = s1 - (carry1 << 21)

  local carry2 = s2 >> 21
  carry2 = carry2 | -(carry2 & 1 << 63 >> 21)
  s3 = s3 + carry2
  s2 = s2 - (carry2 << 21)

  local carry3 = s3 >> 21
  carry3 = carry3 | -(carry3 & 1 << 63 >> 21)
  s4 = s4 + carry3
  s3 = s3 - (carry3 << 21)

  local carry4 = s4 >> 21
  carry4 = carry4 | -(carry4 & 1 << 63 >> 21)
  s5 = s5 + carry4
  s4 = s4 - (carry4 << 21)

  local carry5 = s5 >> 21
  carry5 = carry5 | -(carry5 & 1 << 63 >> 21)
  s6 = s6 + carry5
  s5 = s5 - (carry5 << 21)

  local carry6 = s6 >> 21
  carry6 = carry6 | -(carry6 & 1 << 63 >> 21)
  s7 = s7 + carry6
  s6 = s6 - (carry6 << 21)

  local carry7 = s7 >> 21
  carry7 = carry7 | -(carry7 & 1 << 63 >> 21)
  s8 = s8 + carry7
  s7 = s7 - (carry7 << 21)

  local carry8 = s8 >> 21
  carry8 = carry8 | -(carry8 & 1 << 63 >> 21)
  s9 = s9 + carry8
  s8 = s8 - (carry8 << 21)

  local carry9 = s9 >> 21
  carry9 = carry9 | -(carry9 & 1 << 63 >> 21)
  s10 = s10 + carry9
  s9 = s9 - (carry9 << 21)

  local carry10 = s10 >> 21
  carry10 = carry10 | -(carry10 & 1 << 63 >> 21)
  s11 = s11 + carry10
  s10 = s10 - (carry10 << 21)

  local carry11 = s11 >> 21
  carry11 = carry11 | -(carry11 & 1 << 63 >> 21)
  s12 = s12 + carry11
  s11 = s11 - (carry11 << 21)

  local carry12 = s12 >> 21
  carry12 = carry12 | -(carry12 & 1 << 63 >> 21)
  s13 = s13 + carry12
  s12 = s12 - (carry12 << 21)

  s1 = s1 + s13 * 666643
  s2 = s2 + s13 * 470296
  s3 = s3 + s13 * 654183
  s4 = s4 - s13 * 997805
  s5 = s5 + s13 * 136657
  s6 = s6 - s13 * 683901

  local carry1 = s1 >> 21
  carry1 = carry1 | -(carry1 & 1 << 63 >> 21)
  s2 = s2 + carry1
  s1 = s1 - (carry1 << 21)

  local carry2 = s2 >> 21
  carry2 = carry2 | -(carry2 & 1 << 63 >> 21)
  s3 = s3 + carry2
  s2 = s2 - (carry2 << 21)

  local carry3 = s3 >> 21
  carry3 = carry3 | -(carry3 & 1 << 63 >> 21)
  s4 = s4 + carry3
  s3 = s3 - (carry3 << 21)

  local carry4 = s4 >> 21
  carry4 = carry4 | -(carry4 & 1 << 63 >> 21)
  s5 = s5 + carry4
  s4 = s4 - (carry4 << 21)

  local carry5 = s5 >> 21
  carry5 = carry5 | -(carry5 & 1 << 63 >> 21)
  s6 = s6 + carry5
  s5 = s5 - (carry5 << 21)

  local carry6 = s6 >> 21
  carry6 = carry6 | -(carry6 & 1 << 63 >> 21)
  s7 = s7 + carry6
  s6 = s6 - (carry6 << 21)

  local carry7 = s7 >> 21
  carry7 = carry7 | -(carry7 & 1 << 63 >> 21)
  s8 = s8 + carry7
  s7 = s7 - (carry7 << 21)

  local carry8 = s8 >> 21
  carry8 = carry8 | -(carry8 & 1 << 63 >> 21)
  s9 = s9 + carry8
  s8 = s8 - (carry8 << 21)

  local carry9 = s9 >> 21
  carry9 = carry9 | -(carry9 & 1 << 63 >> 21)
  s10 = s10 + carry9
  s9 = s9 - (carry9 << 21)

  local carry10 = s10 >> 21
  carry10 = carry10 | -(carry10 & 1 << 63 >> 21)
  s11 = s11 + carry10
  s10 = s10 - (carry10 << 21)

  local carry11 = s11 >> 21
  carry11 = carry11 | -(carry11 & 1 << 63 >> 21)
  s12 = s12 + carry11
  s11 = s11 - (carry11 << 21)

  return ("<I8I8I8I8"):pack(
    s1 | s2 << 21 | s3 << 42 | s4 << 63,
    s4 >> 1 | s5 << 20 | s6 << 41 | s7 << 62,
    s7 >> 2 | s8 << 19 | s9 << 40 | s10 << 61,
    s10 >> 3 | s11 << 18 | s12 << 39
  )
end

-- File: src/libsodium/crypto_core/ed25519/ref10/fe_25_5/fe.h.

-- Converts a 32-byte string `s` to a field element.
function fieldFromBytes(s)
  local h1, h2, h3, h4, h5, h6, h7, h8, h9, h10 =
    ("<I4I3I3I3I3I4I3I3I3I3"):unpack(s)
  h2 = h2 << 6
  h3 = h3 << 5
  h4 = h4 << 3
  h5 = h5 << 2
  h7 = h7 << 7
  h8 = h8 << 5
  h9 = h9 << 4
  h10 = (h10 & (1 << 23) - 1) << 2

  local carry10 = h10 + (1 << 24) >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry2 = h2 + (1 << 24) >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry4 = h4 + (1 << 24) >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry6 = h6 + (1 << 24) >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry8 = h8 + (1 << 24) >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry1 = h1 + (1 << 25) >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry3 = h3 + (1 << 25) >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry5 = h5 + (1 << 25) >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry7 = h7 + (1 << 25) >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry9 = h9 + (1 << 25) >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  return {h1, h2, h3, h4, h5, h6, h7, h8, h9, h10}
end

-- local defined earlier
function fieldReduce(h, f)
  local h1, h2, h3, h4, h5, h6, h7, h8, h9, h10 = table.unpack(f, 1, 10)

  local q = 19 * h10 + (1 << 24) >> 25
  q = q | -(q & 1 << 63 >> 25)
  q = q + h1 >> 26
  q = q | -(q & 1 << 63 >> 26)
  q = q + h2 >> 25
  q = q | -(q & 1 << 63 >> 25)
  q = q + h3 >> 26
  q = q | -(q & 1 << 63 >> 26)
  q = q + h4 >> 25
  q = q | -(q & 1 << 63 >> 25)
  q = q + h5 >> 26
  q = q | -(q & 1 << 63 >> 26)
  q = q + h6 >> 25
  q = q | -(q & 1 << 63 >> 25)
  q = q + h7 >> 26
  q = q | -(q & 1 << 63 >> 26)
  q = q + h8 >> 25
  q = q | -(q & 1 << 63 >> 25)
  q = q + h9 >> 26
  q = q | -(q & 1 << 63 >> 26)
  q = q + h10 >> 25
  q = q | -(q & 1 << 63 >> 25)

  h1 = h1 + 19 * q

  local carry1 = h1 >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry2 = h2 >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry3 = h3 >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry4 = h4 >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry5 = h5 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry6 = h6 >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry7 = h7 >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry8 = h8 >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry9 = h9 >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h10 = h10 - (carry10 << 25)

  h[1], h[2], h[3], h[4], h[5], h[6], h[7], h[8], h[9], h[10] =
    h1, h2, h3, h4, h5, h6, h7, h8, h9, h10
end

-- Converts h to a 32-byte string.
local function fieldToBytes(h)
  local t = {}
  fieldReduce(t, h)

  return ("<I8I8I8I8"):pack(
    t[1] | t[2] << 26 | t[3] << 51,
    t[3] >> 13 | t[4] << 13 | t[5] << 38,
    t[6] | t[7] << 25 | t[8] << 51,
    t[8] >> 13 | t[9] << 12 | t[10] << 38
  )
end

lib.fieldFromBytes = fieldFromBytes
lib.fieldReduce = fieldReduce
lib.fieldToBytes = fieldToBytes

--------------------------------------------------------------------------------
-- X25519
--------------------------------------------------------------------------------

-- Performs multiplication of an EC point by a scalar `k`.
--
-- The point is given as a u-coordinate on the curve in its Montgomery form.
--
-- Both arguments are 32-byte strings.
local function x25519(k, u)
  k = {("<I8I8I8I8"):unpack(k)}
  k[5] = nil
  -- clear the 3 least significant bits (so that k % 8 == 0)
  k[1] = k[1] & ~0x7
  -- clear the most significant bit and set the second most significant bit
  k[4] = k[4] & ~(1 << 63) | 1 << 62

  local x1 = fieldFromBytes(u)
  local x2 = field1()
  local z2 = field0()
  local x3 = util.copy(x1)
  local z3 = field1()
  local swap = 0

  local a, aa = {}, {}
  local b, bb = {}, {}
  local e, c, d = {}, {}, {}
  local da, cb = {}, {}

  for t = 254, 0, -1 do
    local kt = k[1 + (t >> 6)] >> (t & 0x3f) & 0x1
    swap = swap ~ kt
    fieldCswap(x2, x3, swap)
    fieldCswap(z2, z3, swap)
    swap = kt

    fieldAdd(a, x2, z2)
    fieldSq(aa, a)
    fieldSub(b, x2, z2)
    fieldSq(bb, b)
    fieldSub(e, aa, bb)
    fieldAdd(c, x3, z3)
    fieldSub(d, x3, z3)
    fieldMul(da, d, a)
    fieldMul(cb, c, b)
    fieldAdd(x3, da, cb)
    fieldSq(x3, x3)
    fieldSub(z3, da, cb)
    fieldSq(z3, z3)
    fieldMul(z3, x1, z3)
    fieldMul(x2, aa, bb)
    fieldMul32(z2, e, 121665)
    fieldAdd(z2, aa, z2)
    fieldMul(z2, e, z2)
  end

  fieldCswap(x2, x3, swap)
  fieldCswap(z2, z3, swap)
  fieldInvert(z2, z2)
  fieldMul(x2, x2, z2)

  return fieldToBytes(x2)
end

lib.x25519 = x25519

local nine = "\9" .. ("\0"):rep(31)
lib.nine = nine

function lib.publicKeyFromPrivate(privKey)
  assert(#privKey == 32)

  return x25519(privKey, nine)
end

function lib.makeKeyGen(rng)
  local function generateKeyPair()
    local privKey = rng(32)
    local pubKey = lib.publicKeyFromPrivate(privKey)

    return {
      public = pubKey,
      private = privKey,
    }
  end

  return generateKeyPair
end

function lib.deriveSharedSecret(selfKeys, otherKeys)
  local sharedSecret = x25519(selfKeys.private, otherKeys.public)

  local setBits = 0

  for i = 1, #sharedSecret, 1 do
    setBits = setBits | sharedSecret:byte(i)
  end

  if setBits == 0 then
    return nil, "other party used small-order element for key exchange"
  end

  return sharedSecret
end

--------------------------------------------------------------------------------
-- Ed25519
--------------------------------------------------------------------------------

-- File: src/libsodium/crypto_sign/ed25519/ref10/open.c.

function lib.verifyEd25519(pubKey, message, signature)
  if #signature ~= 64 then
    return nil, "invalid signature"
  end

  local msb = signature:byte(64)

  if msb & 0xf0 ~= 0 and not scalarIsCanonical(signature:sub(33)) then
    return nil, "invalid signature"
  end

  if not groupIsCanonical(pubKey) then
    return nil, "invalid signature"
  end

  local pa = groupExtendedZero()

  if not groupFromBytesWithSign(pa, pubKey) or groupHasSmallOrder(pa) then
    return nil, "invalid signature"
  end

  local expectedR = groupExtendedZero()

  if not groupFromBytes(expectedR, signature:sub(1, 32))
      or groupHasSmallOrder(expectedR) then
    return nil, "invalid signature"
  end

  local hash = sha2.sha512()
    :update(signature:sub(1, 32))
    :update(pubKey)
    :update(message)
    :finish()
  local k = scalarReduce(hash)

  -- sbpka stands for [s]B + [k]A
  local sbpkaProj = groupProjZero()
  groupDoubleScalarMul(sbpkaProj, k, pa, signature:sub(33))
  local sbpka = groupExtendedZero()
  groupProjToExtended(sbpka, sbpkaProj)
  local check = groupExtendedZero()
  groupExtendedSub(check, expectedR, sbpka)

  if not groupHasSmallOrder(check) then
    return nil, "invalid signature"
  end

  return true
end

return lib

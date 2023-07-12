-- The X25519 key exchange function (using Curve25519).
--
-- A port of the relevant functions from libsodium to Lua.
--
-- Ref:
-- - libsodium. https://github.com/jedisct1/libsodium
-- - RFC 7748. https://datatracker.ietf.org/doc/html/rfc7748
-- - D. J. Bernstein. Curve25519: new Diffie-Hellman speed records. https://cr.yp.to/ecdh/curve25519-20060209.pdf

local util = require("tls13.util")

local lib = {}

--------------------------------------------------------------------------------
-- Computation in GF(2²⁵⁵ - 19), a prime field.
--------------------------------------------------------------------------------
--
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

  local b24 = 1 << 24
  local b25 = 1 << 25

  local carry1 = h1 + b25 >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry2 = h2 + b24 >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry6 = h6 + b24 >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry3 = h3 + b25 >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry7 = h7 + b25 >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry4 = h4 + b24 >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry8 = h8 + b24 >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry9 = h9 + b25 >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 + b24 >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry1 = h1 + b25 >> 26
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

  local b24 = 1 << 24
  local b25 = 1 << 25

  local carry1 = h1 + b25 >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry2 = h2 + b24 >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry6 = h6 + b24 >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry3 = h3 + b25 >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry7 = h7 + b25 >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry4 = h4 + b24 >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry8 = h8 + b24 >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry9 = h9 + b25 >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  local carry10 = h10 + b24 >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry1 = h1 + b25 >> 26
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

  local b24 = 1 << 24
  local b25 = 1 << 25

  local carry10 = h10 + b24 >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry2 = h2 + b24 >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry4 = h4 + b24 >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry6 = h6 + b24 >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry8 = h8 + b24 >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry1 = h1 + b25 >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry3 = h3 + b25 >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry7 = h7 + b25 >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry9 = h9 + b25 >> 26
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

-- File: src/libsodium/crypto_core/ed25519/ref10/fe_25_5/fe.h.

-- Converts a 32-byte string `s` to a field element.
local function fieldFromBytes(s)
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

  local b24 = 1 << 24
  local b25 = 1 << 25

  local carry10 = h10 + b24 >> 25
  carry10 = carry10 | -(carry10 & 1 << 63 >> 25)
  h1 = h1 + carry10 * 19
  h10 = h10 - (carry10 << 25)

  local carry2 = h2 + b24 >> 25
  carry2 = carry2 | -(carry2 & 1 << 63 >> 25)
  h3 = h3 + carry2
  h2 = h2 - (carry2 << 25)

  local carry4 = h4 + b24 >> 25
  carry4 = carry4 | -(carry4 & 1 << 63 >> 25)
  h5 = h5 + carry4
  h4 = h4 - (carry4 << 25)

  local carry6 = h6 + b24 >> 25
  carry6 = carry6 | -(carry6 & 1 << 63 >> 25)
  h7 = h7 + carry6
  h6 = h6 - (carry6 << 25)

  local carry8 = h8 + b24 >> 25
  carry8 = carry8 | -(carry8 & 1 << 63 >> 25)
  h9 = h9 + carry8
  h8 = h8 - (carry8 << 25)

  local carry1 = h1 + b25 >> 26
  carry1 = carry1 | -(carry1 & 1 << 63 >> 26)
  h2 = h2 + carry1
  h1 = h1 - (carry1 << 26)

  local carry3 = h3 + b25 >> 26
  carry3 = carry3 | -(carry3 & 1 << 63 >> 26)
  h4 = h4 + carry3
  h3 = h3 - (carry3 << 26)

  local carry5 = h5 + b25 >> 26
  carry5 = carry5 | -(carry5 & 1 << 63 >> 26)
  h6 = h6 + carry5
  h5 = h5 - (carry5 << 26)

  local carry7 = h7 + b25 >> 26
  carry7 = carry7 | -(carry7 & 1 << 63 >> 26)
  h8 = h8 + carry7
  h7 = h7 - (carry7 << 26)

  local carry9 = h9 + b25 >> 26
  carry9 = carry9 | -(carry9 & 1 << 63 >> 26)
  h10 = h10 + carry9
  h9 = h9 - (carry9 << 26)

  return {h1, h2, h3, h4, h5, h6, h7, h8, h9, h10}
end

local function fieldReduce(h, f)
  local h1, h2, h3, h4, h5, h6, h7, h8, h9, h10 = table.unpack(f, 1, 10)

  local b24 = 1 << 24
  local b25 = 1 << 25

  local q = 19 * h10 + b24 >> 25
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
    local kt = (k[1 + (t >> 6)] >> (t & 0x3f)) & 0x1
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
      private = privateKey,
    }
  end

  return generateKeyPair()
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

return lib

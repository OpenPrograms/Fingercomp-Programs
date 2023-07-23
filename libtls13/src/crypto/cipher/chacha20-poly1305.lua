-- The ChaCha20-Poly1305 AEAD algorithm.
--
-- Ref:
-- - RFC 8439. https://datatracker.ietf.org/doc/html/rfc8439
-- - http://cr.yp.to/mac/poly1305-20050329.pdf

local util = require("tls13.util")

local lib = {}

local roundConstants = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574}

local function chacha20QuarterRound(a, b, c, d)
  a = a + b & 0xffffffff
  d = d ~ a
  d = d << 16 & 0xffffffff | d >> 32 - 16
  c = c + d & 0xffffffff
  b = b ~ c
  b = b << 12 & 0xffffffff | b >> 32 - 12
  a = a + b & 0xffffffff
  d = d ~ a
  d = d << 8 & 0xffffffff | d >> 32 - 8
  c = c + d & 0xffffffff
  b = b ~ c
  b = b << 7 & 0xffffffff | b >> 32 - 7

  return a, b, c, d
end

lib.chacha20QuarterRound = chacha20QuarterRound

local function makeChacha20State(key, counter, nonce)
  assert(#key == 32)
  assert(counter <= 0xffffffff)
  assert(#nonce == 12)

  local s0, s1, s2, s3 = table.unpack(roundConstants, 1, 4)
  local s4, s5, s6, s7, s8, s9, s10, s11 = ("<" .. ("I4"):rep(8)):unpack(key)
  local s13, s14, s15 = ("<I4 I4 I4"):unpack(nonce)

  return {
    s0, s1, s2, s3,
    s4, s5, s6, s7,
    s8, s9, s10, s11,
    counter, s13, s14, s15
  }
end

local function chacha20Block(state)
  local s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15 =
    table.unpack(state, 1, 16)
  assert(s12 <= 0xffffffff)

  for i = 1, 10, 1 do
    s0, s4, s8, s12 = chacha20QuarterRound(s0, s4, s8, s12)
    s1, s5, s9, s13 = chacha20QuarterRound(s1, s5, s9, s13)
    s2, s6, s10, s14 = chacha20QuarterRound(s2, s6, s10, s14)
    s3, s7, s11, s15 = chacha20QuarterRound(s3, s7, s11, s15)

    s0, s5, s10, s15 = chacha20QuarterRound(s0, s5, s10, s15)
    s1, s6, s11, s12 = chacha20QuarterRound(s1, s6, s11, s12)
    s2, s7, s8, s13 = chacha20QuarterRound(s2, s7, s8, s13)
    s3, s4, s9, s14 = chacha20QuarterRound(s3, s4, s9, s14)
  end

  return
    s0 + state[1] & 0xffffffff | s1 + state[2] << 32,
    s2 + state[3] & 0xffffffff | s3 + state[4] << 32,
    s4 + state[5] & 0xffffffff | s5 + state[6] << 32,
    s6 + state[7] & 0xffffffff | s7 + state[8] << 32,
    s8 + state[9] & 0xffffffff | s9 + state[10] << 32,
    s10 + state[11] & 0xffffffff | s11 + state[12] << 32,
    s12 + state[13] & 0xffffffff | s13 + state[14] << 32,
    s14 + state[15] & 0xffffffff | s15 + state[16] << 32
end

function lib.chacha20Block(key, counter, nonce)
  return ("<" .. ("I8"):rep(8)):pack(
    chacha20Block(makeChacha20State(key, counter, nonce))
  )
end

lib.chacha20 = {
  BLOCK_SIZE = 64,
  KEY_SIZE = 32,
}

function lib.chacha20:encrypt(plaintext, key, nonce, counter)
  assert(#key == 32)
  assert(counter <= 0xffffffff)
  assert(#nonce == 12)

  counter = counter or 0

  local result = {}
  local i8x8 = "<" .. ("I8"):rep(8)
  local blockCount = util.idivCeil(#plaintext, 64)
  local state = makeChacha20State(key, counter, nonce)

  for i = 1, blockCount, 1 do
    local start = i - 1 << 6
    local block = plaintext:sub(start + 1, start + 64)
    local paddedBlock = block

    if #block < 64 then
      paddedBlock = block .. ("\0"):rep(64 - #block)
    end

    local b1, b2, b3, b4, b5, b6, b7, b8 = i8x8:unpack(paddedBlock)
    state[13] = counter + i - 1
    local k1, k2, k3, k4, k5, k6, k7, k8 = chacha20Block(state)

    local encryptedBlock = i8x8:pack(
      b1 ~ k1,
      b2 ~ k2,
      b3 ~ k3,
      b4 ~ k4,
      b5 ~ k5,
      b6 ~ k6,
      b7 ~ k7,
      b8 ~ k8
    ):sub(1, #block)

    table.insert(result, encryptedBlock)
  end

  return table.concat(result)
end

lib.chacha20.decrypt = lib.chacha20.encrypt

local function clampKey(hi, lo)
  return
    hi & 0x0ffffffc0ffffffc,
    lo & 0x0ffffffc0fffffff
end

local function poly1305Mac(self, message, key)
  assert(#key == self.KEY_SIZE)

  -- a 130-bit integer is represented as 5 26-bit integers.
  -- (4 would leave no room for carries).
  local r1 = ("<i4"):unpack(key, 1) & 0x3ffffff
  local r2 = ("<i4"):unpack(key, 4) >> 2 & 0x3ffff03
  local r3 = ("<i4"):unpack(key, 7) >> 4 & 0x3ffc0ff
  local r4 = ("<i4"):unpack(key, 10) >> 6 & 0x3f03fff
  local r5 = ("<i3"):unpack(key, 14) & 0x00fffff

  -- for modular reduction.
  local r2t5 = r2 * 5
  local r3t5 = r3 * 5
  local r4t5 = r4 * 5
  local r5t5 = r5 * 5

  local a1, a2, a3, a4, a5 = 0, 0, 0, 0, 0

  for i = 1, #message, 16 do
    local block = message:sub(i, i + 15) .. "\1"
    local paddedBlock = block

    if #block < 17 then
      paddedBlock = block .. ("\0"):rep(17 - #block)
    end

    -- add the block to the accumulator.
    a1 = a1 + (("<i4"):unpack(paddedBlock, 1) & 0x3ffffff)
    a2 = a2 + (("<i4"):unpack(paddedBlock, 4) >> 2 & 0x3ffffff)
    a3 = a3 + (("<i4"):unpack(paddedBlock, 7) >> 4 & 0x3ffffff)
    a4 = a4 + (("<i4"):unpack(paddedBlock, 10) >> 6 & 0x3ffffff)
    a5 = a5 + ("<i4"):unpack(paddedBlock, 14)

    -- multiply by r and reduce high-order words at the same time
    -- (this is easy since 2¹³⁰ ≡ 5 (mod p)).
    a1, a2, a3, a4, a5 =
      a1 * r1 + a2 * r5t5 + a3 * r4t5 + a4 * r3t5 + a5 * r2t5,
      a1 * r2 + a2 * r1 + a3 * r5t5 + a4 * r4t5 + a5 * r3t5,
      a1 * r3 + a2 * r2 + a3 * r1 + a4 * r5t5 + a5 * r4t5,
      a1 * r4 + a2 * r3 + a3 * r2 + a4 * r1 + a5 * r5t5,
      a1 * r5 + a2 * r4 + a3 * r3 + a4 * r2 + a5 * r1

    -- propagate carries.
    a1, a2 = a1 & 0x3ffffff, a2 + (a1 >> 26)
    a2, a3 = a2 & 0x3ffffff, a3 + (a2 >> 26)
    a3, a4 = a3 & 0x3ffffff, a4 + (a3 >> 26)
    a4, a5 = a4 & 0x3ffffff, a5 + (a4 >> 26)
    a5, a1 = a5 & 0x3ffffff, a1 + 5 * (a5 >> 26)
    -- once more: the carry after multiplication by 5 may be a tad too big
    -- (assuming that somehow a1, ..., a5 = 5 * 0x3ffffff * 0x3ffffff).
    a1, a2 = a1 & 0x3ffffff, a2 + (a1 >> 26)
  end

  -- propagate carries once more (just in case).
  a2, a3 = a2 & 0x3ffffff, a3 + (a2 >> 26)
  a3, a4 = a3 & 0x3ffffff, a4 + (a3 >> 26)
  a4, a5 = a4 & 0x3ffffff, a5 + (a4 >> 26)
  a5, a1 = a5 & 0x3ffffff, a1 + 5 * (a5 >> 26)
  a1, a2 = a1 & 0x3ffffff, a2 + (a1 >> 26)

  -- in the (very unlikely, admittedly) case that a >= p, we have to subtract p:
  --   a - p = a - 2¹³⁰ + 5.
  local amp1 = a1 + 5
  local amp2 = a2
  local amp3 = a3
  local amp4 = a4
  local amp5 = a5 - (1 << 26)
  amp1, amp2 = amp1 & 0x3ffffff, amp2 + (amp1 >> 26)
  amp2, amp3 = amp2 & 0x3ffffff, amp3 + (amp2 >> 26)
  amp3, amp4 = amp3 & 0x3ffffff, amp4 + (amp3 >> 26)
  amp4, amp5 = amp4 & 0x3ffffff, amp5 + (amp4 >> 26)

  -- how to tell if a < p? amp5 will be negative in this case.
  -- grab the sign bit and do a conditional move.
  local mask = -(amp5 >> 63)
  a1 = amp1 ~ (amp1 ~ a1) & mask
  a2 = amp2 ~ (amp2 ~ a2) & mask
  a3 = amp3 ~ (amp3 ~ a3) & mask
  a4 = amp4 ~ (amp4 ~ a4) & mask
  a5 = amp5 ~ (amp5 ~ a5) & mask

  -- at this point we only need to do 128-bit arithmetic.
  -- convert a to a pair of 64-bit integers.
  local lo = a1 | a2 << 26 | a3 << 52
  local hi = a3 >> 12 | a4 << 14 | a5 << 40

  -- add s = key >> 128.
  local sLo, sHi = ("<I8 I8"):unpack(key, 17)
  local loAdded = lo + sLo
  -- carry == 1 iff lo and sLo both have the msb set
  -- or either of them has and the result doesn't
  local carry = ((lo & sLo | (lo | sLo) & ~loAdded) >> 63)
  lo = loAdded
  hi = hi + sHi + carry

  return ("<I8 I8"):pack(lo, hi)
end

lib.poly1305 = setmetatable({
  BLOCK_SIZE = 16,
  KEY_SIZE = 32,
}, {__call = poly1305Mac})

local meta

local function makeChacha20Poly1305(self, key)
  assert(#key == lib.chacha20Poly1305.KEY_SIZE, "key must be 32 bytes long")

  return setmetatable({__key = key}, meta)
end

lib.chacha20Poly1305 = setmetatable({
  BLOCK_SIZE = 64,
  KEY_SIZE = 32,
  IV_SIZE = 12,
  TAG_SIZE = 16,
}, {__call = makeChacha20Poly1305})

function lib.poly1305KeyGen(key, nonce)
  return ("<" .. ("I8"):rep(4)):pack(
    chacha20Block(makeChacha20State(key, 0, nonce))
  )
end

local function getMacData(aad, ciphertext)
  return table.concat({
    aad, ("\0"):rep(util.computePadding2(#aad, 16)),
    ciphertext, ("\0"):rep(util.computePadding2(#ciphertext, 16)),
    ("<I8 I8"):pack(#aad, #ciphertext),
  })
end

meta = {
  __index = {
    BLOCK_SIZE = lib.chacha20Poly1305.BLOCK_SIZE,
    KEY_SIZE = lib.chacha20Poly1305.KEY_SIZE,
    IV_SIZE = lib.chacha20Poly1305.IV_SIZE,
    TAG_SIZE = lib.chacha20Poly1305.TAG_SIZE,

    getLength = function(self, plaintextLength)
      return plaintextLength + lib.chacha20Poly1305.TAG_SIZE
    end,

    encrypt = function(self, plaintext, iv, aad)
      assert(#iv == lib.chacha20Poly1305.IV_SIZE, "IV must be 12 bytes long")

      local key = self.__key
      local macKey = lib.poly1305KeyGen(key, iv)
      local ciphertext = lib.chacha20:encrypt(plaintext, key, iv, 1)
      local macData = getMacData(aad, ciphertext)
      local tag = lib.poly1305(macData, macKey)

      return ciphertext .. tag
    end,

    decrypt = function(self, ciphertextWithTag, iv, aad)
      assert(#iv == lib.chacha20Poly1305.IV_SIZE, "IV must be 12 bytes long")

      local ciphertext = ciphertextWithTag:sub(1, -17)
      local tag = ciphertextWithTag:sub(-16)
      tag = tag .. ("\0"):rep(16 - #tag)

      local key = self.__key
      local macKey = lib.poly1305KeyGen(key, iv)
      local plaintext = lib.chacha20:decrypt(ciphertext, key, iv, 1)
      local macData = getMacData(aad, ciphertext)
      local actualTag = lib.poly1305(macData, macKey)

      local bits = 0

      for i = 1, 16, 1 do
        bits = bits | tag:byte(i) ~ actualTag:byte(i)
      end

      if bits ~= 0 then
        return nil, "decryption failed"
      end

      return plaintext
    end,
  },
}

return lib

-- The Galois/counter block cipher mode (GCM).
--
-- Ref:
-- - https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
-- - https://csrc.nist.rip/groups/ST/toolkit/BCM/documents/proposedmodes/gcm/gcm-revised-spec.pdf

local util = require("tls13.util")

local lib = {}

-- The incrementing function.
local function inc(x, s)
  local mask = (1 << s) - 1

  return x & ~mask | (x + 1) & mask
end

-- Multiplies the little-endian polynomial hi:lo by x in GF(2¹²⁸).
local function mulx(hi, lo)
  -- return hi << 1 | lo >> 63, lo << 1 ~ 0x87 & -(hi >> 63)
  -- the large constant is the generating polynomial mask
  return
    hi >> 1 ~ -(lo & 1) & 0xe100000000000000,
    lo >> 1 | (hi & 1) << 63
end

-- the remainders of reverse(i) * x^128 in GF(2¹²⁸)
local remainders = {}

do
  for i = 1, 255, 1 do
    remainders[i] = -1
  end

  remainders[0] = 0
  remainders[0x80] = 0xe100000000000000

  local i = 0x40

  repeat
    remainders[i] = remainders[i << 1] >> 1
    i = i >> 1
  until i == 0

  i = 2

  repeat
    for j = 1, i - 1, 1 do
      remainders[i + j] = remainders[i] ~ remainders[j]
    end

    i = i << 1
  until i == 256
end

-- Computes a lookup table for `mul128`.
local function computeMulLut(hi, lo)
  -- a 256-entry table of 128 words
  -- the ith entry is lut[i << 1 | 1] : lut[i << 1]
  local lut = {}

  -- initializes the array part of `lut`
  for i = 1, 511, 1 do
    lut[i] = -1
  end

  lut[0x80 << 1 | 1] = hi
  lut[0x80 << 1] = lo

  local i = 0x40

  repeat
    lut[i << 1 | 1], lut[i << 1] = mulx(lut[i << 2 | 1], lut[i << 2])
    i = i >> 1
  until i == 0

  i = 2

  repeat
    local hi, lo = lut[i << 1 | 1], lut[i << 1]

    for j = 1, i - 1, 1 do
      lut[i + j << 1 | 1], lut[i + j << 1] =
        hi ~ lut[j << 1 | 1],
        lo ~ lut[j << 1]
    end

    i = i << 1
  until i == 256

  lut[0 | 1], lut[0] = 0, 0

  return lut
end

-- Multiplies a 128-bit little-endian polynomial by `h` in GF(2¹²⁸)
-- using a LUT for `h`.
local function mul128(lut, inputHi, inputLo)
  -- BearSSL has a few nice tricks for constant-time multiplication:
  -- https://www.bearssl.org/constanttime.html#ghash-for-gcm
  -- I'm not concerned about security here,
  -- but adopting those might actually make mul128 faster.
  --
  -- Maybe later.

  local hi, lo = 0, 0

  for i = 1, 15, 1 do
    local byte = inputLo & 0xff
    hi, lo =
      hi ~ lut[byte << 1 | 1],
      lo ~ lut[byte << 1]
    hi, lo =
      hi >> 8 ~ remainders[lo & 0xff],
      lo >> 8 | hi << 56
    inputHi, inputLo =
      inputHi >> 8,
      inputLo >> 8 | inputHi << 56
  end

  local byte = inputLo & 0xff

  return
    hi ~ lut[byte << 1 | 1],
    lo ~ lut[byte << 1]
end

local function ghash(block, lut)
  assert(#block & 15 == 0, "block length must be divisible by 16")

  local hi, lo = 0, 0

  for pos = 1, #block, 16 do
    local blockHi, blockLo = (">I8I8"):unpack(block, pos)
    blockHi = blockHi ~ hi
    blockLo = blockLo ~ lo
    hi, lo = mul128(lut, blockHi, blockLo)
  end

  return hi, lo
end

local function gctr(plaintext, key, cipher, icbHi, icbLo)
  if #plaintext == "" then
    return ""
  end

  -- the first 12 bytes stay the same whereas the lower 4 change
  -- we store hi as a string and lo as an int to allow incrementing the latter
  local counterHi = (">I8I4"):pack(icbHi, icbLo >> 32)
  local counterLo = icbLo & 0xffffffff

  local result = {}
  local blockCount = util.idivCeil(#plaintext, 16)
  local pos = 1

  for i = 1, blockCount, 1 do
    local blockHi, blockLo

    if i ~= blockCount then
      blockHi, blockLo = (">I8I8"):unpack(plaintext, pos)
    else
      local finalBlock = plaintext:sub(pos)
      blockHi, blockLo = (">I8I8"):unpack(
        finalBlock .. ("\0"):rep(util.computePadding2(#finalBlock, 128))
      )
    end

    local xorBlockHi, xorBlockLo = (">I8I8"):unpack(
      cipher:encrypt(counterHi .. (">I4"):pack(counterLo), key)
    )

    blockHi = blockHi ~ xorBlockHi
    blockLo = blockLo ~ xorBlockLo

    if i ~= blockCount then
      table.insert(result, (">I8I8"):pack(blockHi, blockLo))
    else
      table.insert(
        result,
        (">I8I8"):pack(blockHi, blockLo):sub(1, #plaintext - pos + 1)
      )
    end

    pos = pos + 16
    counterLo = (counterLo + 1) & 0xffffffff
  end

  return table.concat(result)
end


local meta = {
  __index = {
    getLength = function(self, plaintextLength, aadLength)
      return
        plaintextLength
        + (self.__aead and 16 or 0) -- tag
    end,

    encrypt = function(self, plaintext, iv, aad)
      assert(#iv == 12, "IV must be 12 bytes long")

      local cipher = self.__cipher
      local icbHi, icbLo = (">I8I8"):unpack(iv .. "\0\0\0\1")

      local ciphertext =
        gctr(plaintext, self.__key, cipher, icbHi, inc(icbLo, 32))

      local finalBlock = table.concat({
        aad,
        ("\0"):rep(util.computePadding2(#aad, 16)),
        ciphertext,
        ("\0"):rep(util.computePadding2(#ciphertext, 16)),
        (">I8I8"):pack(#aad * 8, #ciphertext * 8),
      })
      local tag = gctr(
        (">I8I8"):pack(ghash(finalBlock, self.__lut)),
        self.__key,
        cipher,
        icbHi,
        icbLo
      )

      if self.__aead then
        return ciphertext .. tag
      end

      return ciphertext, tag
    end,

    decrypt = function(self, ciphertext, tag, iv, aad)
      if self.__aead then
        assert(aad == nil)

        ciphertext, tag, iv, aad =
          ciphertext:sub(1, -17),
          ciphertext:sub(-16),
          tag,
          iv
      end

      assert(#iv == 12, "IV must be 12 bytes long")

      if #tag ~= 16 then
        return nil, "decryption failed"
      end

      local cipher = self.__cipher
      local icbHi, icbLo = (">I8I8"):unpack(iv .. "\0\0\0\1")

      local plaintext =
        gctr(ciphertext, self.__key, cipher, icbHi, inc(icbLo, 32))

      local finalBlock = table.concat({
        aad,
        ("\0"):rep(util.computePadding2(#aad, 16)),
        ciphertext,
        ("\0"):rep(util.computePadding2(#ciphertext, 16)),
        (">I8I8"):pack(#aad * 8, #ciphertext * 8),
      })
      local actualTag = gctr(
        (">I8I8"):pack(ghash(finalBlock, self.__lut)),
        self.__key,
        cipher,
        icbHi,
        icbLo
      )

      if tag ~= actualTag then
        return nil, "decryption failed"
      end

      return plaintext
    end,
  },
}

local function makeGcm(self, key)
  local lut = computeMulLut(
    (">I8I8"):unpack(self.__cipher:encrypt(("\0"):rep(16), key))
  )

  return setmetatable({
    BLOCK_SIZE = self.BLOCK_SIZE,
    KEY_SIZE = self.KEY_SIZE,
    IV_SIZE = self.IV_SIZE,
    TAG_SIZE = self.TAG_SIZE,

    __aead = self.__aead,
    __cipher = self.__cipher,
    __key = key,
    __lut = lut,
  }, meta)
end

-- Creates a GCM cipher factory based on the provided 128-bit block cipher.
--
-- Setting `aead` to `true` embeds authentication tag into the ciphertext.
lib.gcm = function(cipher, aead)
  assert(cipher.BLOCK_SIZE == 16, "unsupported cipher block size")

  return setmetatable({
    BLOCK_SIZE = cipher.BLOCK_SIZE,
    KEY_SIZE = cipher.KEY_SIZE,
    IV_SIZE = 12,
    TAG_SIZE = 16,

    __aead = aead,
    __cipher = cipher,
  }, {__call = makeGcm})
end

lib.__internal = {
  mulx = mulx,
  computeMulLut = computeMulLut,
  mul128 = mul128,
  ghash = ghash,
}

return lib

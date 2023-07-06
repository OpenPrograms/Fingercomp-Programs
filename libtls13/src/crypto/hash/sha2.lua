-- The SHA2 hash functions: SHA2-256, SHA2-384, SHA2-512.
--
-- Ref:
-- - RFC 6234. https://www.rfc-editor.org/rfc/rfc6234

local util = require("tls13.util")
local buffer = require("tls13.util.buffer")

local ror32 = util.ror32
local ror64 = util.ror64

local lib = {}

local function makeSha2(args)
  local chunkSize = args.chunkSize
  local wordSize = args.wordSize
  local hashSize = args.hashSize
  local processChunk = args.processChunk
  local initialHash = args.initialHash
  local messageLengthSize = args.messageLengthSize

  local resultWordCount = hashSize * 8 // wordSize
  local resultPattern = (">I" .. (wordSize // 8)):rep(resultWordCount)

  local meta

  meta = {
    __index = {
      HASH_SIZE = hashSize,

      -- Appends `chunk` to the message.
      --
      -- Returns `self` for chaining.
      update = function(self, chunk)
        assert(self.__buf:remaining() < chunkSize)

        self.__buf:append(chunk)

        while self.__buf:remaining() >= chunkSize do
          self:_processChunk(self.__buf:consume(chunkSize))
        end

        return self
      end,

      -- Finalizes the hash computation, padding the message as necessary.
      -- Returns the computed hash as a byte string.
      --
      -- The hasher instance should not be used after this call.
      finish = function(self)
        assert(self.__buf:remaining() < chunkSize)

        local messageBitLength =
          (self.__processedChunkCount * chunkSize + self.__buf:remaining()) * 8
        local finalChunkUnpaddedLength =
          self.__buf:remaining()
          -- the 0b1000_0000 byte immediately following the message
          + 1
          -- the message length
          + messageLengthSize
        local paddingLength =
          util.computePadding2(finalChunkUnpaddedLength, chunkSize)
        local finalBlock =
          "\x80"
          .. ("\0"):rep(paddingLength)
          .. (">I" .. messageLengthSize):pack(messageBitLength)

        self:update(finalBlock)
        assert(self.__buf:remaining() == 0)

        return resultPattern:pack(table.unpack(self.__hash))
      end,

      -- Copies the hash state to a new instance.
      copy = function(self)
        return setmetatable({
          __hash = util.copy(self.__hash),
          __buf = self.__buf:copy(),
          __processedChunkCount = self.__processedChunkCount,
        }, meta)
      end,

      _processChunk = processChunk,
    },
  }

  local function new(self)
    return setmetatable({
      __hash = table.move(initialHash, 1, #initialHash, 1, {}),
      __buf = buffer.makeBuffer(),
      __processedChunkCount = 0,
    }, meta)
  end

  return setmetatable({
    BLOCK_SIZE = chunkSize,
    HASH_SIZE = hashSize,
  }, {__call = new})
end

do
  -- SHA2-256

  local roundConstants = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  }

  lib.sha256 = makeSha2 {
    chunkSize = 64,
    wordSize = 32,
    hashSize = 32,
    messageLengthSize = 8,

    initialHash = {
      0x6a09e667,
      0xbb67ae85,
      0x3c6ef372,
      0xa54ff53a,
      0x510e527f,
      0x9b05688c,
      0x1f83d9ab,
      0x5be0cd19,
    },

    processChunk = function(self, chunk)
      assert(#chunk == 64)

      -- split the chunk into 32-bit words
      local msgSchedule = {(">I4"):rep(16):unpack(chunk)}

      -- prepare the message schedule
      for i = 17, 64, 1 do
        local word15 = msgSchedule[i - 15]
        local sigma0 =
          ror32(word15, 7)
          ~ ror32(word15, 18)
          ~ (word15 >> 3)

        local word2 = msgSchedule[i - 2]
        local sigma1 =
          ror32(word2, 17)
          ~ ror32(word2, 19)
          ~ (word2 >> 10)

        local result =
          sigma1 + msgSchedule[i - 7] + sigma0 + msgSchedule[i - 16]
        msgSchedule[i] = result & 0xffffffff
      end

      local a, b, c, d, e, f, g, h = table.unpack(self.__hash)

      -- the compression loop
      for i = 1, 64, 1 do
        local sigma0 =
          ror32(a, 2)
          ~ ror32(a, 13)
          ~ ror32(a, 22)
        local sigma1 =
          ror32(e, 6)
          ~ ror32(e, 11)
          ~ ror32(e, 25)
        local choice = (e & f) ~ (~e & g)
        local majority = (a & b) ~ (a & c) ~ (b & c)

        local t1 = h + sigma1 + choice + roundConstants[i] + msgSchedule[i]
        local t2 = sigma0 + majority
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2
      end

      self.__hash[1] = (a + self.__hash[1]) & 0xffffffff
      self.__hash[2] = (b + self.__hash[2]) & 0xffffffff
      self.__hash[3] = (c + self.__hash[3]) & 0xffffffff
      self.__hash[4] = (d + self.__hash[4]) & 0xffffffff
      self.__hash[5] = (e + self.__hash[5]) & 0xffffffff
      self.__hash[6] = (f + self.__hash[6]) & 0xffffffff
      self.__hash[7] = (g + self.__hash[7]) & 0xffffffff
      self.__hash[8] = (h + self.__hash[8]) & 0xffffffff

      self.__processedChunkCount = self.__processedChunkCount + 1
    end,
  }
end

do
  -- SHA2-384 and SHA2-512

  local roundConstants = {
    0x428a2f98d728ae22, 0x7137449123ef65cd,
    0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019,
    0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe,
    0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1,
    0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3,
    0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483,
    0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210,
    0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725,
    0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926,
    0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8,
    0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001,
    0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910,
    0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
    0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb,
    0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60,
    0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9,
    0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207,
    0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6,
    0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493,
    0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a,
    0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
  }

  local function processChunk(self, chunk)
    assert(#chunk == 128)

    -- split the chunk into 64-bit words
    local msgSchedule = {(">I8"):rep(16):unpack(chunk)}

    -- prepare the message schedule
    for i = 17, 80, 1 do
      local word15 = msgSchedule[i - 15]
      local sigma0 =
        ror64(word15, 1)
        ~ ror64(word15, 8)
        ~ (word15 >> 7)

      local word2 = msgSchedule[i - 2]
      local sigma1 =
        ror64(word2, 19)
        ~ ror64(word2, 61)
        ~ (word2 >> 6)

      msgSchedule[i] =
        sigma1 + msgSchedule[i - 7] + sigma0 + msgSchedule[i - 16]
    end

    local a, b, c, d, e, f, g, h = table.unpack(self.__hash)

    -- the compression loop
    for i = 1, 80, 1 do
      local sigma0 =
        ror64(a, 28)
        ~ ror64(a, 34)
        ~ ror64(a, 39)
      local sigma1 =
        ror64(e, 14)
        ~ ror64(e, 18)
        ~ ror64(e, 41)
      local choice = (e & f) ~ (~e & g)
      local majority = (a & b) ~ (a & c) ~ (b & c)

      local t1 = h + sigma1 + choice + roundConstants[i] + msgSchedule[i]
      local t2 = sigma0 + majority
      h = g
      g = f
      f = e
      e = d + t1
      d = c
      c = b
      b = a
      a = t1 + t2
    end

    self.__hash[1] = a + self.__hash[1]
    self.__hash[2] = b + self.__hash[2]
    self.__hash[3] = c + self.__hash[3]
    self.__hash[4] = d + self.__hash[4]
    self.__hash[5] = e + self.__hash[5]
    self.__hash[6] = f + self.__hash[6]
    self.__hash[7] = g + self.__hash[7]
    self.__hash[8] = h + self.__hash[8]

    self.__processedChunkCount = self.__processedChunkCount + 1
  end

  lib.sha384 = makeSha2 {
    chunkSize = 128,
    wordSize = 64,
    hashSize = 48,
    messageLengthSize = 16,

    initialHash = {
      0xcbbb9d5dc1059ed8,
      0x629a292a367cd507,
      0x9159015a3070dd17,
      0x152fecd8f70e5939,
      0x67332667ffc00b31,
      0x8eb44a8768581511,
      0xdb0c2e0d64f98fa7,
      0x47b5481dbefa4fa4,
    },

    processChunk = processChunk,
  }

  lib.sha512 = makeSha2 {
    chunkSize = 128,
    wordSize = 64,
    hashSize = 64,
    messageLengthSize = 16,

    initialHash = {
      0x6a09e667f3bcc908,
      0xbb67ae8584caa73b,
      0x3c6ef372fe94f82b,
      0xa54ff53a5f1d36f1,
      0x510e527fade682d1,
      0x9b05688c2b3e6c1f,
      0x1f83d9abfb41bd6b,
      0x5be0cd19137e2179,
    },

    processChunk = processChunk,
  }
end

return lib

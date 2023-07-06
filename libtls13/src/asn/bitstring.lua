-- ASN.1 BITSTRING implementation.

local util = require("tls13.util")

local lib = {}

local makeBitstring

local methods = {
  -- Returns the bit with a provided index in the bitstring,
  -- indexed left-to-right (starting from zero).
  get = function(self, idx)
    if idx < 0 or idx > #self then
      return nil
    end

    local wordIdx = (idx >> 6) + 1
    local bitIdx = idx & 0x3f

    return self.__words[wordIdx] & 1 << 63 >> bitIdx ~= 0
  end,

  set = function(self, idx, value)
    if idx < 0 then
      return
    end

    util.checkArg(3, value, "boolean")

    local wordIdx = (idx >> 6) + 1
    local bitIdx = idx & 0x3f
    local words = self.__words

    if #words < wordIdx then
      for i = #words + 1, wordIdx, 1 do
        words[i] = 0
      end

      self.__padding = 64
    end

    if #words == wordIdx and bitIdx + self.__padding >= 64 then
      self.__padding = 63 - bitIdx
    end

    if value then
      words[wordIdx] = words[wordIdx] | 1 << 63 >> bitIdx
    else
      words[wordIdx] = words[wordIdx] & ~(1 << 63 >> bitIdx)
    end
  end,

  copy = function(self)
    return makeBitstring(util.copy(self.__words), self.__padding)
  end,

  shiftLeft = function(self, n)
    local wordShift = n >> 6
    local bitShift = n & 0x3f
    local words = self.__words

    for i = 1, #words - wordShift - 1, 1 do
      words[i] =
        words[i + wordShift] << bitShift
        | words[i + wordShift + 1] >> 64 - bitShift
    end

    local lastWordIdx = #words - wordShift

    if lastWordIdx >= 1 then
      words[lastWordIdx] = words[lastWordIdx] << bitShift
    end

    local wordCount = #words

    for i = 1, self.__padding + n >> 6, 1 do
      words[wordCount - i + 1] = nil
    end

    self.__padding = self.__padding + n & 0x3f
  end,

  shiftRight = function(self, n)
    local wordShift = n >> 6
    local bitShift = n & 0x3f
    local words = self.__words
    local wordCount = #words

    if bitShift > self.__padding then
      words[wordCount + wordShift + 1] =
        (words[wordCount] or 0) << 64 - bitShift
    end

    for i = wordCount, 2, -1 do
      words[i + wordShift] =
        words[i] >> bitShift
        | words[i - 1] << 64 - bitShift
    end

    if wordCount >= 1 then
      words[wordShift + 1] = words[1] >> bitShift
    end

    for i = 1, wordShift, 1 do
      words[i] = 0
    end

    self.__padding = self.__padding - bitShift & 0x3f
  end,

  toHex = function(self)
    if #self.__words == 0 then
      return ""
    end

    local chunks = {}

    for i = 1, #self.__words - 1, 1 do
      chunks[i] = ("%016x"):format(self.__words[i])
    end

    chunks[#chunks + 1] = ("%x"):format(
      self.__words[#self.__words] >> self.__padding
    )

    return table.concat(chunks)
  end,

  toBytes = function(self)
    if #self.__words == 0 then
      return ""
    end

    local chunks = {}

    for i = 1, #self.__words - 1, 1 do
      chunks[i] = (">I8"):pack(self.__words[i])
    end

    chunks[#chunks + 1] =
      (">I8"):pack(self.__words[#self.__words])
        :sub(1, 8 - (self.__padding >> 3))

    return table.concat(chunks)
  end,

  alignRight = function(self)
    self:shiftRight(self.__padding)
  end,

  toBigint = function(self)
    if #self.__words == 0 then
      return {0}
    end

    local padding = self.__padding

    if padding > 0 then
      self:shiftRight(padding)
    end

    local result = {}

    for i = #self.__words, 2, -1 do
      local word = self.__words[i]
      table.insert(result, word & 0xffffffff)
      table.insert(result, word >> 32)
    end

    table.insert(result, self.__words[1] & 0xffffffff)

    if padding < 32 then
      table.insert(result, self.__words[1] >> 32)
    end

    if padding > 0 then
      self:shiftLeft(padding)
    end

    return result
  end,

  padding = function(self)
    return self.__padding
  end,

  isByteAligned = function(self)
    return self.__padding & 0x7 == 0
  end,

  byte = function(self, n)
    n = n - 1
    local wordIdx = n >> 3
    local bitShift = (n & 0x7) << 3

    local word = self.__words[wordIdx + 1]

    if not word then
      return 0
    end

    return word >> 56 - bitShift & 0xff
  end,

  leastSignificantWord = function(self, signed)
    if #self.__words == 0 then
      return 0
    elseif #self.__words == 1 then
      if signed then
        return
          self.__words[1] >> self.__padding
          -- sign-extend
          | -(1 << 64 - self.__padding)
      else
        return self.__words[1] >> self.__padding
      end
    else
      local words = self.__words

      if signed then
        return
          -- the low-order bits
          words[#words] >> self.__padding
          -- the high-order bits
          | words[#words - 1] << 64 - self.__padding & (1 << 63) - 1
          -- and the sign bit
          | words[1] & 1 << 63
      else
        return
          words[#words] >> self.__padding
          | words[#words - 1] << 64 - self.__padding
      end
    end
  end,
}

local meta = {
  -- Returns the number of bits stored in the bitstring.
  __len = function(self)
    return (#self.__words << 6) - self.__padding
  end,

  __index = function(self, k)
    if type(k) == "number" then
      return self:get(k)
    end

    return methods[k]
  end,

  -- Sets the kth bit to value.
  __newindex = function(self, k, value)
    self:set(k, value)
  end,

  __shr = function(self, n)
    local result = self:copy()
    result:shiftRight(n)

    return result
  end,

  __shl = function(self, n)
    local result = self:copy()
    result:shiftLeft(n)

    return result
  end,

  __tostring = function(self)
    return self:toHex()
  end,

  __eq = function(self, other)
    if getmetatable(self) ~= getmetatable(other) or #self ~= #other then
      return false
    end

    for i = 1, #self.__words, 1 do
      if self.__words[i] ~= other.__words[i] then
        return false
      end
    end

    return true
  end,
}

local function makeBitstring(words, paddingBits)
  return setmetatable({
    __words = words,
    __padding = paddingBits,
  }, meta)
end

function lib.empty()
  return makeBitstring({}, 0)
end

function lib.fromHex(s)
  local words = {}
  local padding = 0

  for i = 1, #s, 16 do
    local word = s:sub(i, i + 15)
    padding = 16 - #word << 2

    table.insert(words, tonumber(word, 16) << padding)
  end

  return makeBitstring(words, padding)
end

function lib.fromBytes(s, unusedBits)
  unusedBits = unusedBits or 0
  assert(unusedBits >= 0 and unusedBits < 8)

  local words = {}
  local padding = (8 - #s & 0x7) & 0x7

  for i = 1, #s, 8 do
    if i + 8 <= #s then
      table.insert(words, ((">I8"):unpack(s, i)))
    else
      table.insert(
        words,
        (">I" .. (8 - padding)):unpack(s, i) << (padding << 3)
      )
    end
  end

  if #words > 0 then
    words[#words] = words[#words] & ~((1 << unusedBits) - 1)
  end

  return makeBitstring(words, (padding << 3) + unusedBits)
end

return lib

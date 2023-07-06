-- Various utilities.

local lib = {}

-- Encodes a byte string `s` as a hex string.
function lib.toHex(s)
  return (s:gsub(".", function(c) return ("%02x"):format(c:byte()) end))
end

-- Decodes a hex string `s` as a byte string.
function lib.fromHex(s)
  return (s:gsub("%x%x", function(xx) return string.char(tonumber(xx, 16)) end))
end

-- Rotates a 32-bit word `x` right by `n` bits.
function lib.ror32(x, n)
  return ((x & 0xffffffff) >> n) | (x << (32 - n)) & 0xffffffff
end

-- Rotates a 64-bit word `x` right by `n` bits.
function lib.ror64(x, n)
  return (x >> n) | (x << (64 - n))
end

-- Returns how many padding bytes are needed for `inputSize` to get aligned.
--
-- The alignment must be a power of two.
function lib.computePadding2(inputSize, alignment)
  local mask = alignment - 1
  assert(alignment & mask == 0, "alignment is not a power of two")

  return alignment - (inputSize & mask) & mask
end

-- Rounds `inputSize` up to the nearest multiple of `alignment`.
--
-- The alignment must be a power of two.
function lib.alignUp2(inputSize, alignment)
  local mask = alignment - 1
  assert(alignment & mask == 0, "alignment is not a power of two")

  return inputSize + mask & ~mask
end

-- Performs integer division, rounding up.
function lib.idivCeil(a, b)
  return (a + b - 1) // b
end

-- Removes the first `n` elements from an array and shifts the rest.
function lib.removeShift(tbl, n)
  table.move(tbl, n + 1, n + #tbl, 1)
end

-- Makes a shallow copy of a sequence.
function lib.copy(tbl)
  return table.move(tbl, 1, #tbl, 1, {})
end

-- Makes a shallow copy of a map.
function lib.copyMap(tbl)
  local result = {}

  for k, v in pairs(tbl) do
    result[k] = v
  end

  return result
end

-- Reverses the order of elements in a sequence.
function lib.reverse(tbl)
  local n = #tbl + 1

  for i = 1, #tbl // 2, 1 do
    local ri = n - i
    tbl[i], tbl[ri] = tbl[ri], tbl[i]
  end
end

-- Creates a new table with keys and values swapped.
function lib.swapPairs(tbl)
  local result = {}

  for k, v in pairs(tbl) do
    result[v] = k
  end

  return result
end

-- Counts the number of leading zeros in a 64-bit word.
function lib.nlz64(n)
  -- fill the rest of the word with ones and count the number of zeros
  n = n | n >> 1
  n = n | n >> 2
  n = n | n >> 4
  n = n | n >> 8
  n = n | n >> 16
  n = n | n >> 32

  return lib.popCount(~n)
end

-- Returns the index of the last leading zero bit.
-- This is the same as `64 - nlz64(x)`.
function lib.lastLeadingZero(n)
  -- see nlz64 for explanation
  n = n | n >> 1
  n = n | n >> 2
  n = n | n >> 4
  n = n | n >> 8
  n = n | n >> 16
  n = n | n >> 32

  return lib.popCount(n)
end

-- Returns the number of bits set in a 64-bit word (population count).
function lib.popCount(n)
  -- maps aligned 11 groups to 10, counting the number of bits in each group
  n = n - (n >> 1 & 0x5555555555555555)
  -- counts the number of bits in each 4-bit group
  n = (n & 0x3333333333333333) + (n >> 2 & 0x3333333333333333)
  -- in each 8-bit group
  n = (n + (n >> 4)) & 0x0f0f0f0f0f0f0f0f
  -- in each 16-bit group (max, 64, now fits in a group, so no masking)
  n = n + (n >> 8)
  -- in each 32-bit group
  n = n + (n >> 16)
  -- in the whole word
  n = n + (n >> 32)

  return n & 0x7f
end

-- Performs a bitwise XOR on two byte strings.
-- Their lengths must be equal.
function lib.xorBytes(lhs, rhs)
  assert(#lhs == #rhs)

  local parts = {}

  for i = 1, #lhs, 8 do
    local lhsChunk = lhs:sub(i, i + 7)
    local rhsChunk = rhs:sub(i, i + 7)

    if i + 8 < #lhs then
      table.insert(parts, ("I8"):pack(
        ("I8"):unpack(lhsChunk) ~ ("I8"):unpack(rhsChunk)
      ))
    else
      local paddingCount = i + 7 - #lhs
      local padding = ("\0"):rep(paddingCount)
      table.insert(
        parts,
        (">I8")
          :pack(
            (">I8"):unpack(padding .. lhsChunk)
            ~ (">I8"):unpack(padding .. rhsChunk)
          )
          :sub(paddingCount + 1)
      )
    end
  end

  return table.concat(parts)
end

do
  local meta = {
    __index = {
      next = function(self)
        local result = self.__value
        self.__value = result + 1

        return result
      end,

      get = function(self)
        return self.__value
      end,

      resetTo = function(self, value)
        local result = self.__value
        self.__value = value

        return result
      end,
    },

    __len = function(self)
      return self:get()
    end,
  }

  -- Makes a new counter that can be incremented.
  function lib.makeCounter(init)
    init = init or 1

    return setmetatable({__value = init}, meta)
  end
end

lib.checkArg = checkArg or function(n, have, ...)
  have = type(have)
  local function check(want, ...)
    if not want then
      return false
    else
      return have == want or check(...)
    end
  end
  if not check(...) then
    local msg = string.format("bad argument #%d (%s expected, got %s)",
                              n, table.concat({...}, " or "), have)
    error(msg, 3)
  end
end

-- Returns true if an `element` is a member of a sequence `tbl`.
function lib.contains(tbl, element)
  for _, v in ipairs(tbl) do
    if v == element then
      return true
    end
  end

  return false
end

-- Returns the key and value of the pair whose value matches a predicate.
-- The table is treated as a sequence.
function lib.find(tbl, predicate)
  for k, value in ipairs(tbl) do
    if predicate(value) then
      return k, value
    end
  end

  return nil
end

-- Makes a map from a sequence by applying a projection to get entry keys.
function lib.sequenceToMap(tbl, keyProjection)
  local result = {}

  for _, value in ipairs(tbl) do
    local key = keyProjection(value)

    if result[key] == nil then
      result[key] = value
    end
  end

  return result
end

-- Makes a function that returns a field of its argument.
function lib.projectKey(key)
  return function(tbl)
    return tbl[key]
  end
end

-- Applies a function to every sequence element to produce a new sequence.
function lib.map(tbl, f)
  local result = {}

  for _, value in ipairs(tbl) do
    table.insert(result, (f(value)))
  end

  return result
end

-- Creates a copy of lhs with rhs entries appended.
function lib.append(lhs, rhs)
  local result = lib.copy(lhs)

  for _, value in ipairs(rhs) do
    table.insert(result, value)
  end

  return result
end

return lib

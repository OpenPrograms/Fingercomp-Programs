-- Base64 encoding facilities.

local util = require("tls13.util")

local lib = {}

lib.defaultAlphabet = {}

for i = 1, 26, 1 do
  table.insert(lib.defaultAlphabet, string.char(("A"):byte() + i - 1))
end

for i = 1, 26, 1 do
  table.insert(lib.defaultAlphabet, string.char(("a"):byte() + i - 1))
end

for i = 0, 9, 1 do
  table.insert(lib.defaultAlphabet, string.char(("0"):byte() + i))
end

table.insert(lib.defaultAlphabet, "+")
table.insert(lib.defaultAlphabet, "/")

lib.defaultInverseAlphabet = util.swapPairs(lib.defaultAlphabet)

local function calculatePadding(encoded)
  local count = 0

  for i = #encoded, 1, -1 do
    if encoded:sub(i, i) == "=" then
      count = count + 1
    else
      break
    end
  end

  if count > 2 then
    return nil, "invalid padding"
  end

  return count
end

function lib.decode(encoded, inverseAlphabet)
  inverseAlphabet = inverseAlphabet or lib.defaultInverseAlphabet

  if #encoded % 4 ~= 0 then
    return nil, "base64-encoded data length must be divisible by 4"
  end

  local padding, err = calculatePadding(encoded)

  if not padding then
    return nil, err
  end

  local result = {}

  for i = 1, #encoded, 4 do
    local bits = 0

    for j = 1, 4, 1 do
      local pos = i + j - 1
      local byte = encoded:sub(pos, pos)

      if byte == "=" and pos > #encoded - padding then
        byte = 0
      elseif byte == "=" then
        return nil, "found equals sign not part of padding at pos " .. pos
      else
        byte = inverseAlphabet[byte] - 1
      end

      bits = bits << 6 | byte
    end

    local bytes = 3

    if i + 4 > #encoded then
      bytes = 3 - padding
    end

    table.insert(result, (">BBB"):sub(1, bytes + 1):pack(
      bits >> 16,
      bits >> 8 & 0xff,
      bits & 0xff
    ))
  end

  return table.concat(result)
end

function lib.encode(data, alphabet)
  alphabet = alphabet or lib.defaultAlphabet

  local result = {}

  for i = 1, #data, 3 do
    if i + 2 <= #data then
      local bits = (">I3"):unpack(data, i)
      result[i + 0] = alphabet[bits >> 18]
      result[i + 1] = alphabet[bits >> 12 & 0x3f]
      result[i + 2] = alphabet[bits >> 6 & 0x3f]
      result[i + 3] = alphabet[bits & 0x3f]
    elseif i + 1 <= #data then
      local bits = (">I2"):unpack(data, i)
      result[i + 0] = alphabet[bits >> 10]
      result[i + 1] = alphabet[bits >> 4 & 0x3f]
      result[i + 2] = alphabet[bits << 2 & 0x3f]
      result[i + 3] = "="
    else
      local bits = data:byte(i)
      result[i + 0] = alphabet[bits >> 2]
      result[i + 1] = alphabet[bits << 4 & 0x3f]
      result[i + 2] = "="
      result[i + 3] = "="
    end
  end

  return table.concat(result)
end

return lib

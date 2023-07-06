-- The HMAC function.
--
-- Ref:
-- - RFC 2104. https://www.rfc-editor.org/rfc/rfc2104.html

local lib = {}

local function xorByteString(s, byte)
  return (
    s:gsub("()(.)", function(i, c)
      return string.char(c:byte() ~ byte)
    end)
  )
end

-- Creates a HMAC function with the given `hash` function.
--
-- The returned function is of signature `function(data, key)`.
function lib.hmac(hash)
  local blockSize = hash.BLOCK_SIZE

  local function hmac(self, data, key)
    if #key > blockSize then
      key = hash():update(key):finish()
    end

    local digest = hash()
      :update(xorByteString(key, 0x36) .. ("\x36"):rep(blockSize - #key))
      :update(data)
      :finish()

    return hash()
      :update(xorByteString(key, 0x5c) .. ("\x5c"):rep(blockSize - #key))
      :update(digest)
      :finish()
  end

  return setmetatable({
    BLOCK_SIZE = blockSize,
    HASH_SIZE = hash.HASH_SIZE,
  }, {__call = hmac})
end

return lib

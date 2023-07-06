-- The HMAC-based key derivation function.
--
-- Ref:
-- - RFC 5869. https://rfc-editor.org/rfc/rfc5869.html

local lib = {}

local meta = {
  __index = {
    extract = function(self, ikm, salt)
      if not salt then
        salt = ("\0"):rep(self.__hmac.HASH_SIZE)
      end

      return self.__hmac(ikm, salt)
    end,

    expand = function(self, context, len, key)
      local hashLen = self.__hmac.HASH_SIZE
      assert(#key >= hashLen)
      assert(len <= hashLen * 255)

      local chunks = {}

      for i = 1, len, hashLen do
        table.insert(chunks, self.__hmac(
          ("%s%s%s"):format(
            chunks[#chunks] or "",
            context,
            string.char(#chunks + 1)
          ),
          key
        ))
      end

      local resultLen = #chunks * hashLen

      if len < resultLen then
        chunks[#chunks] = chunks[#chunks]:sub(1, -(resultLen - len) - 1)
      end

      local result = table.concat(chunks)

      return result
    end,
  },
}

function lib.hkdf(hmac)
  return setmetatable({
    __hmac = hmac,
  }, meta)
end

return lib

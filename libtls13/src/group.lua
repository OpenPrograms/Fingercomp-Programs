-- Named groups for key exchange.

local curve25519 = require("tls13.crypto.curve25519")

local lib = {}

function lib.makeX25519(rng)
  local keyGen = curve25519.makeKeyGen(rng)

  return {
    decodePublicKey = function(self, keyExchange)
      if #keyExchange ~= 32 then
        return nil, "invalid share"
      end

      return {public = keyExchange}
    end,

    encodePublicKey = function(self, keys)
      return keys.public
    end,

    generateKeyPair = function(self)
      return keyGen()
    end,

    deriveSharedSecret = function(self, clientShare, serverShare)
      return curve25519.deriveSharedSecret(clientShare, serverShare)
    end,
  }
end

return lib

-- RSA-based signature verification algorithms: RSASSA-PSS, RSASSA-PKCS#1-v1.5.
--
-- Ref:
-- - RFC 8017. https://www.rfc-editor.org/rfc/rfc8017.html

local asnEncode = require("tls13.asn.encode")
local montgomery = require("tls13.crypto.montgomery")
local util = require("tls13.util")

local lib = {}

-- Constructs a mask generation function MGF1, defined in RFC 8017, with a given
-- hash function.
function lib.mgf1(hash)
  local hashLen = hash.HASH_SIZE

  local function mgf1(seed, maskLen)
    assert(maskLen <= hashLen << 32, "mask is too long")

    local parts = {}
    local resultSize = 0

    for i = 0, util.idivCeil(maskLen, hashLen) - 1, 1 do
      local part = hash():update(seed):update((">I4"):pack(i)):finish()

      if resultSize + #part > maskLen then
        part = part:sub(1, maskLen - resultSize)
      end

      table.insert(parts, part)
      resultSize = resultSize + #part
    end

    local result = table.concat(parts)
    assert(#result == maskLen)

    return result
  end

  return mgf1
end

-- The RSA verification primitive, version 1.
function lib.rsaVp1(pubKey, signatureBigint)
  if montgomery.cmp(signatureBigint, pubKey.modulus) >= 0 then
    return nil, "signature representative is out of range"
  end

  return montgomery.modPowOdd(signatureBigint, pubKey.exponent, pubKey.modulus)
end

do
  local meta = {
    __index = {
      -- Verifies an RSASSA-PSS signature.
      -- Returns `true` if the signature is valid.
      verify = function(self, pubKey, message, signature)
        if #signature ~= pubKey.modulusSize then
          return false
        end

        local signatureBigint = montgomery.fromBytes(signature)
        local messageBigint = lib.rsaVp1(pubKey, signatureBigint)

        if not messageBigint then
          return false
        end

        local modulusBitCount = pubKey.modulusBitCount
        local messageLen = util.idivCeil(modulusBitCount - 1, 8)
        local encodedMessage =
          montgomery.toBytes(messageBigint, messageLen)

        if not encodedMessage then
          return false
        end

        return self:_emsaPssVerify(message, encodedMessage, modulusBitCount - 1)
      end,

      _emsaPssVerify = function(self, message, encodedMessage, messageBitCount)
        local hashLen = self.__hash.HASH_SIZE
        local messageHash = self.__hash():update(message):finish()

        if #encodedMessage < hashLen + self.__saltLen + 2 then
          return false
        end

        if encodedMessage:sub(-1) ~= "\xbc" then
          return false
        end

        local maskedDataBlock = encodedMessage:sub(1, -hashLen - 2)
        local hash = encodedMessage:sub(-hashLen - 1, -2)
        local lastByteBits = messageBitCount & 0x7

        if lastByteBits > 0 and maskedDataBlock:byte() >> lastByteBits ~= 0 then
          -- high-order bits must be zero
          return false
        end

        local dataBlockMask =
          self.__maskGen(hash, #encodedMessage - hashLen - 1)
        local dataBlock = util.xorBytes(maskedDataBlock, dataBlockMask)
        local padding = dataBlock:sub(1, -self.__saltLen - 1)

        for i = 1, #padding, 1 do
          local byte = padding:byte(i)

          if i == 1 then
            -- clear the high bits
            byte = byte & ((1 << lastByteBits) - 1)
          end

          if i < #padding and byte ~= 0 or i == #padding and byte ~= 1 then
            -- invalid padding
            return false
          end
        end

        local salt = ""

        if self.__saltLen ~= 0 then
          salt = dataBlock:sub(-self.__saltLen)
        end

        local expectedHash = self.__hash()
          :update(("\0"):rep(8))
          :update(messageHash)
          :update(salt)
          :finish()

        return hash == expectedHash
      end,
    },
  }

  function lib.rsassaPss(hash, maskGen, saltLen)
    return setmetatable({
      __hash = hash,
      __maskGen = maskGen,
      __saltLen = saltLen or hash.HASH_SIZE,
    }, meta)
  end
end

do
  local meta = {
    __index = {
      -- Verifies an RSASSA-PKCS#1-v1.5 signature.
      -- Returns `true` if the signature is valid.
      --
      -- In case of error, returns a `nil` and an error message.
      verify = function(self, pubKey, message, signature)
        local modulusSize = pubKey.modulusSize

        if #signature ~= modulusSize then
          return false
        end

        local signatureBigint = montgomery.fromBytes(signature)
        local messageBigint = lib.rsaVp1(pubKey, signatureBigint)

        if not messageBigint then
          return false
        end

        local encodedMessage = montgomery.toBytes(messageBigint, modulusSize)

        if not encodedMessage then
          return false
        end

        local expectedMessage, err =
          self:_emsaPkcs1V15Encode(message, modulusSize)

        if not expectedMessage then
          return nil, err
        end

        return expectedMessage == encodedMessage
      end,

      _emsaPkcs1V15Encode = function(self, message, encodedMessageLength)
        local hash = self.__hash():update(message):finish()

        -- and now we encode the hash into an ASN.1 value, i kid you not.
        local asn = asnEncode.encodeSequence({
          -- algorithm
          asnEncode.encodeSequence({
            -- algorithm
            asnEncode.encodeObjectIdentifier(self.__hashOid),
            -- parameters
            asnEncode.encodeNull(),
          }),
          -- digest
          asnEncode.encodeOctetString(hash),
        })

        if encodedMessageLength < #asn + 11 then
          return nil, "intended encoded message length is too short"
        end

        local padding = encodedMessageLength - #asn - 3

        return ("\0\1%s\0%s"):format(("\xff"):rep(padding), asn)
      end,
    },
  }

  function lib.rsassaPkcs1V15(hash, hashOid)
    return setmetatable({
      __hash = hash,
      __hashOid = hashOid,
    }, meta)
  end
end

function lib.makePublicKey(modulusBigint, exponentBigint)
  local modulusBitCount = montgomery.bitCount(modulusBigint)
  local modulusSize = util.idivCeil(modulusBitCount, 8)

  return {
    modulus = modulusBigint,
    modulusSize = modulusSize,
    modulusBitCount = modulusBitCount,
    exponent = exponentBigint,
  }
end

function lib.makePublicKeyFromHex(modulusHex, exponentHex)
  local modulusBigint = montgomery.fromHex(modulusHex)
  local exponentBigint = montgomery.fromHex(exponentHex)

  return lib.makePublicKey(modulusBigint, exponentBigint)
end

function lib.makePublicKeyFromBytes(modulusBytes, exponentBytes)
  local modulusBigint = montgomery.fromBytes(modulusHex)
  local exponentBigint = montgomery.fromBytes(exponentHex)

  return lib.makePublicKey(modulusBigint, exponentBigint)
end

return lib

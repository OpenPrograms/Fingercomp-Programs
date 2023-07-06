-- OpenComputers signature algorithms.

local asnEncode = require("tls13.asn.encode")
local errors = require("tls13.error")
local oc = require("tls13.oc")
local oid = require("tls13.asn.oid")

local lib = {}

-- OC /does/ have secp384r1, but for unknowable reasons not ECDSA with sha384
-- (not that it has sha384 at all anyway...)

function lib.makeEcdsaSecp256r1SigAlg()
  local data = oc.getDataCard()

  return {
    decodePublicKey = function(self, pkInfo)
      if pkInfo.algorithm.algorithm ~= oid.ansiX962.keyType.ecPublicKey then
        return nil, errors.x509.publicKeyInvalid.subject(
          "algorithm OID is invalid"
        )
      end

      if pkInfo.algorithm.parameters.namedCurve
          ~= oid.ansiX962.curves.prime.prime256r1 then
        return nil, errors.x509.publicKeyInvalid.subject("unsupported curve")
      end

      -- it's a bit wasteful to decode and then encode back...
      -- but whatever.
      local encoded = asnEncode.encodeSequence({
        -- algorithm
        asnEncode.encodeSequence({
          -- algorithm
          asnEncode.encodeObjectIdentifier(oid.ansiX962.keyType.ecPublicKey),
          -- parameters
          asnEncode.encodeObjectIdentifier(
            oid.ansiX962.curves.prime.prime256r1
          ),
        }),
        -- subjectPublicKey
        asnEncode.encodeBitString(pkInfo.subjectPublicKey),
      })

      local key, err = data.deserializeKey(encoded, "ec-public")

      if not key then
        return nil, errors.x509.publicKeyInvalid.subject(err)
      end

      return key
    end,

    verify = function(self, publicKey, signedMessage, signature)
      return data.ecdsa(signedMessage, publicKey, signature)
    end,

    sign = function(self, privateKey, message)
      return data.ecdsa(message, privateKey)
    end,
  }
end

return lib

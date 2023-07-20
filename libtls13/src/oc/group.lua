-- OpenComputers named groups for key exchange.

local asn = require("tls13.asn")
local asnEncode = require("tls13.asn.encode")
local bitstring = require("tls13.asn.bitstring")
local oc = require("tls13.oc")
local oid = require("tls13.asn.oid")

local lib = {}

lib.curveOids = {
  [256] = oid.ansiX962.curves.prime.prime256r1,
  [384] = oid.iso.identifiedOrganization.certicom.curve.ansip384r1,
}

function lib.makeEcdhe(bitCount)
  local data = oc.getDataCard()
  local curveOid = assert(lib.curveOids[bitCount])

  return {
    decodePublicKey = function(self, keyExchange)
      -- we have to encode as SubjectPublicKeyInfo so that OC accepts
      -- the point...
      -- rather wasteful.

      -- keyExchange is an EC point in the uncompressed format
      -- (RFC 8446, §4.2.8.2)
      -- X.509 subjectPublicKey stores this immediately as an OCTET STRING
      -- (RFC 5480, §2.2)
      local encoded = asnEncode.encodeSequence({
        -- algorithm
        asnEncode.encodeSequence({
          -- algorithm
          asnEncode.encodeObjectIdentifier(oid.ansiX962.keyType.ecPublicKey),
          -- parameters
          asnEncode.encodeObjectIdentifier(curveOid),
        }),
        -- subjectPublicKey
        asnEncode.encodeBitString(bitstring.fromBytes(keyExchange)),
      })

      local key, err = data.deserializeKey(encoded, "ec-public")

      if not key then
        return nil, err
      end

      return {public = key}
    end,

    encodePublicKey = function(self, keys)
      -- note that Java 8 does not support the compressed form at all,
      -- so the serialized data is exactly what we need for TLS
      -- (after unwrapping the outer layers, of course).

      -- but if the produced value is something we don't expect,
      -- we'd like to abort the whole thing because it's not a user error
      local decoded = assert(asn.decode(keys.public.serialize()))
      assert(decoded.TAG == asn.asnTags.universal.sequence, "expected SEQUENCE")
      assert(#decoded == 2, "expected 2 top-level fields")

      local algorithm = decoded[1]
      local subjectPublicKey = decoded[2]

      assert(
        algorithm.TAG == asn.asnTags.universal.sequence,
        "algorithm must be SEQUENCE"
      )
      assert(
        subjectPublicKey.TAG == asn.asnTags.universal.bitString,
        "subjectPublicKey must be BIT STRING"
      )

      -- just make sure it's the curve we need...
      assert(#algorithm == 2, "algorithm must have 2 fields")
      local algorithmOid = algorithm[1]
      local parameters = algorithm[2]

      assert(
        algorithmOid.TAG == asn.asnTags.universal.objectIdentifier,
        "algorithm.algorithm must be OBJECT IDENTIFIER"
      )
      assert(
        algorithmOid[1] == oid.ansiX962.keyType.ecPublicKey,
        "wrong algorithm.algorithm value (must be ecPublicKey)"
      )
      assert(
        parameters.TAG == asn.asnTags.universal.objectIdentifier,
        "algorithm.parameters must be OBJECT IDENTIFIER"
      )
      assert(parameters[1] == curveOid, "wrong curve OID")

      -- technically it could also be 0x00 (the point at infinity),
      -- but it's rather useless as a key
      assert(
        subjectPublicKey[1]:byte(1) == 0x04,
        "point format must be uncompressed"
      )
      assert(
        subjectPublicKey[1]:isByteAligned(),
        "public key must be byte-aligned"
      )

      -- the first byte describes the format, which we've already checked
      -- the rest are the X and Y coordinates, each `bitCount / 8` bytes long
      local encoded = subjectPublicKey[1]:toBytes()
      assert(#encoded - 1 == bitCount >> 3 << 1, "invalid length")

      return encoded
    end,

    generateKeyPair = function(self)
      local pubKey, privKey = data.generateKeyPair(bitCount)

      return {
        public = pubKey,
        private = privKey,
      }
    end,

    deriveSharedSecret = function(self, clientShare, serverShare)
      return data.ecdh(clientShare.private, serverShare.public)
    end,
  }
end

return lib

-- TLS signature algorithms.

local asn = require("tls13.asn")
local curve25519 = require("tls13.crypto.curve25519")
local errors = require("tls13.error")
local oid = require("tls13.asn.oid")
local rsa = require("tls13.crypto.rsa")
local secp384r1 = require("tls13.crypto.secp384r1")

local lib = {}

function lib.decodeRsaPublicKey(pkInfo)
  local subjectPublicKey = pkInfo.subjectPublicKey

  if not subjectPublicKey:isByteAligned() then
    return nil, errors.x509.publicKeyInvalid.subject(
      "bitstring must be byte-aligned"
    )
  end

  local decoded, err = asn.decode(subjectPublicKey:toBytes())

  if not decoded then
    return nil, errors.x509.publicKeyInvalid.subject(err)
  end

  if decoded.TAG ~= asn.asnTags.universal.sequence then
    return nil, errors.x509.publicKeyInvalid.subject(
      "enclosing tag must be SEQUENCE"
    )
  end

  local modulus = decoded[1]
  local exponent = decoded[2]

  if not modulus or modulus.TAG ~= asn.asnTags.universal.integer then
    return nil, errors.x509.publicKeyInvalid.subject(
      "modulus is not present or is not INTEGER"
    )
  end

  if not exponent or exponent.TAG ~= asn.asnTags.universal.integer then
    return nil, errors.x509.publicKeyInvalid.subject(
      "public exponent is not present or is not INTEGER"
    )
  end

  if #decoded ~= 2 then
    return nil, errors.x509.publicKeyInvalid.subject(
      "decoded public key has superfluous fields"
    )
  end

  if modulus.long then
    modulus = modulus[1]:toBigint()
  else
    modulus = {modulus[1]}
  end

  if exponent.long then
    exponent = exponent[1]:toBigint()
  else
    exponent = {exponent[1]}
  end

  if modulus[1] & 0x1 ~= 1 then
    -- an even modulus is, like, so bad it's not even RSA
    -- AND it will trigger an assertion failure during multiplication
    return nil, errors.x509.publicKeyInvalid.subject("modulus must be odd")
  end

  if exponent[1] & 0x1 ~= 1 then
    -- such an exponent can never be coprime with λ(n)
    -- (well, provided n is not divisible by two,
    -- which we take for granted here)
    return nil,
      errors.x509.publicKeyInvalid.subject("public exponent must be odd")
  end

  -- it's also a good idea to ensure that 3 ≤ e < n and n ≥ 2¹⁰²³,
  -- but I'm a bit too lazy for that.
  return rsa.makePublicKey(modulus, exponent)
end

function lib.decodeRsaePublicKey(subjectPkInfo)
  if subjectPkInfo.algorithm.algorithm ~= oid.pkcs1.rsaEncryption then
    return nil, errors.x509.publicKeyInvalid.subject(
      "unsupported algorithm OID"
    )
  end

  return lib.decodeRsaPublicKey(subjectPkInfo)
end

function lib.makeRsaPkcs1SigAlg(hash, hashOid)
  local pkcs1 = rsa.rsassaPkcs1V15(hash, hashOid)

  return {
    decodePublicKey = function(self, pkInfo)
      return lib.decodeRsaePublicKey(pkInfo)
    end,

    verify = function(self, publicKey, signedMessage, signature)
      return pkcs1:verify(publicKey, signedMessage, signature)
    end,

    -- not implemented
    sign = nil,
  }
end

function lib.decodeRsaPssPublicKey(pkInfo, hashOid, saltLength)
  if pkInfo.algorithm.algorithm ~= oid then
    return nil, errors.x509.publicKeyInvalid.subject(
      "unsupported algorithm OID"
    )
  end

  local parameters = pkInfo.algorithm.parameters

  if parameters.hashAlgorithm.algorithm ~= hashOid then
    return nil, errors.x509.publicKeyInvalid.subject(
      "parameters.hashAlgorithm is invalid"
    )
  end

  if parameters.maskGenAlgorithm.algorithm ~= oid.pkcs1.mgf1 then
    return nil, errors.x509.publicKeyInvalid.subject(
      "parameters.maskGenAlgorithm.algorithm is invalid"
    )
  end

  if parameters.maskGenAlgorithm.parameters.algorithm ~= hashOid then
    return nil, errors.x509.publicKeyInvalid.subject(
      "parameters.maskGenAlgorithm.algorithm.parameters.algorithm is invalid"
    )
  end

  if parameters.saltLength ~= saltLength then
    return nil, errors.x509.publicKeyInvalid.subject(
      "parameters.saltLength is invalid"
    )
  end

  return lib.decodeRsaPublicKey(pkInfo)
end

function lib.makeRsaPssRsaeSigAlg(hash)
  local pss = rsa.rsassaPss(hash, rsa.mgf1(hash), hash.HASH_SIZE)

  return {
    decodePublicKey = function(self, pkInfo)
      return lib.decodeRsaePublicKey(pkInfo)
    end,

    verify = function(self, publicKey, signedMessage, signature)
      return pss:verify(publicKey, signedMessage, signature)
    end,

    -- not implemented
    sign = nil,
  }
end

function lib.makeRsaPssPssSigAlg(hash, hashOid)
  local pss = rsa.rsassaPss(hash, rsa.mgf1(hash), hash.HASH_SIZE)

  return {
    decodePublicKey = function(self, pkInfo)
      return lib.decodeRsaPssPublicKey(pkInfo, hashOid, hash.HASH_SIZE)
    end,

    verify = function(self, publicKey, signedMessage, signature)
      return pss:verify(publicKey, signedMessage, signature)
    end,

    -- not implemented
    sign = nil,
  }
end

function lib.decodeEd25519PublicKey(pkInfo)
  local subjectPublicKey = pkInfo.subjectPublicKey

  if #subjectPublicKey ~= 256 then
    return nil, errors.x509.publicKeyInvalid.subject(
      "public key must be 256 bits long"
    )
  end

  return subjectPublicKey:toBytes()
end

function lib.makeEd25519SigAlg()
  return {
    decodePublicKey = function(self, pkInfo)
      if pkInfo.algorithm.algorithm ~= oid.edDSA25519 then
        return nil, errors.x509.publicKeyInvalid.subject(
          "unsupported algorithm OID"
        )
      end

      return lib.decodeEd25519PublicKey(pkInfo)
    end,

    verify = function(self, publicKey, signedMessage, signature)
      return curve25519.verifyEd25519(publicKey, signedMessage, signature)
    end,

    sign = function(self, privateKey, message)
      return curve25519.signEd25519(privateKey, message)
    end,
  }
end

function lib.decodeEcdsaSignature(signature)
  local decoded, err = asn.decode(signature)

  if not decoded then
    return nil, "invalid DER encoding"
  end

  if decoded.TAG ~= asn.asnTags.universal.sequence then
    return nil, "top-level tag is not SEQUENCE"
  end

  local r = decoded[1]
  local s = decoded[2]

  if not r or r.TAG ~= asn.asnTags.universal.integer then
    return nil, "r is absent or not INTEGER"
  end

  if not s or s.TAG ~= asn.asnTags.universal.integer then
    return nil, "s is absent or not INTEGER"
  end

  if #decoded > 2 then
    return nil, "extraneous elements present"
  end

  local rNegative, sNegative

  if r.long then
    rNegative = r[1][0]
  else
    rNegative = r[1] < 0
  end

  if s.long then
    sNegative = s[1][0]
  else
    sNegative = s[1] < 0
  end

  if rNegative or sNegative then
    return nil, "r or s is negative"
  end

  local sr = r.long and r[1]:toBytes() or (">I8"):pack(r[1])
  local ss = s.long and s[1]:toBytes() or (">I8"):pack(s[1])

  -- skip trailing zeros
  if #sr == 49 and sr:byte() == 0 then
    sr = sr:sub(2)
  end

  if #ss == 49 and ss:byte() == 0 then
    ss = ss:sub(2)
  end

  return sr, ss
end

function lib.makeEcdsaSecp384r1SigAlg()
  return {
    decodePublicKey = function(self, pkInfo)
      if pkInfo.algorithm.algorithm ~= oid.ansiX962.keyType.ecPublicKey then
        return nil, errors.x509.publicKeyInvalid.subject(
          "algorithm OID is invalid"
        )
      end

      if pkInfo.algorithm.parameters.namedCurve
          ~= oid.iso.identifiedOrganization.certicom.curve.ansip384r1 then
        return nil, errors.x509.publicKeyInvalid.subject("unsupported curve")
      end

      return pkInfo.subjectPublicKey:toBytes()
    end,

    verify = function(self, publicKey, signedMessage, signature)
      local sr, ss = lib.decodeEcdsaSignature(signature)

      if not sr then
        return false
      end

      local success, err =
        secp384r1.ecdsaVerifySha384(signedMessage, sr, ss, publicKey)

      return success and true or false
    end,

    -- not implemented
    sign = nil,
  }
end

return lib

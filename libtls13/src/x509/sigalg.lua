-- Recognized X.509 certificate signature algorithms.

local asn = require("tls13.asn")
local errors = require("tls13.error")
local oid = require("tls13.asn.oid")
local util = require("tls13.util")
local utilMap = require("tls13.util.map")

local lib = {}

lib.recognizedSignatureAlgorithms = utilMap.makeProjectionMap(tostring)

function lib.makeSigAlg(name, parser)
  return {
    getName = function()
      return name
    end,

    parseParameters = function(self, p, value, hasSignatureValue)
      return parser(p, value, hasSignatureValue)
    end,
  }
end

function lib.makeNoParamSigAlg(name)
  return lib.makeSigAlg(name, function(parser, value)
    if value then
      return nil, parser:makeError(
        errors.x509.algorithmParametersPresent,
        value.TAG
      )
    end

    return false
  end)
end

function lib.makeNullParamSigAlg(name)
  return lib.makeSigAlg(name, function(parser, value)
    if not value then
      return nil, parser:makeError(errors.x509.algorithmParametersOmitted)
    end

    local value, err = parser:checkTag(value, asn.asnTags.universal.null)

    if not value then
      return nil, err
    end

    return false
  end)
end

function lib.makeNoOrNullParamSigAlg(name)
  return lib.makeSigAlg(name, function(parser, value)
    if not value then
      return false
    end

    local value, err = parser:checkTag(value, asn.asnTags.universal.null)

    if not value then
      return nil, err
    end

    return false
  end)
end

lib.recognizedSignatureAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA256
] = lib.makeNoParamSigAlg("ecdsa-with-SHA256")
lib.recognizedSignatureAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA384
] = lib.makeNoParamSigAlg("ecdsa-with-SHA384")
lib.recognizedSignatureAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA512
] = lib.makeNoParamSigAlg("ecdsa-with-SHA512")

-- not really a signature algorithm, but eh.
lib.recognizedSignatureAlgorithms[oid.ansiX962.keyType.ecPublicKey] =
  lib.makeSigAlg("ecPublicKey", function(parser, value)
    local result, err = {}
    result.namedCurve, err = parser:parseOid(value)

    if not result.namedCurve then
      return nil, err
    end

    return result
  end)

-- this one neither.
lib.recognizedSignatureAlgorithms[oid.pkcs1.rsaEncryption] =
  lib.makeNullParamSigAlg("rsaEncryption")

local function parseExplicit(parser, value, f, ...)
  local value, err = parser:checkExplicitTag(value)

  if not value then
    return nil, err
  end

  return f(parser, value, ...)
end

lib.recognizedSignatureAlgorithms[oid.pkcs1.rsassaPss] =
  lib.makeSigAlg("RSASSA-PSS", function(parser, value, hasSignatureValue)
    if not value and hasSignatureValue then
      return nil, parser:makeError(errors.x509.algorithmParametersOmitted)
    end

    if not value then
      return false
    end

    local fieldIdx = util.makeCounter()
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    result.hashAlgorithm = {
      algorithm = oid.sha1,
      parameters = false,
    }

    if value[#fieldIdx]
        and value[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 0) then
      result.hashAlgorithm, err = parser:withField(
        value,
        fieldIdx:next(),
        "hashAlgorithm",
        parseExplicit,
        parser.parseAlgorithmIdentifier
      )

      if not result.hashAlgorithm then
        return nil, err
      end
    end

    result.maskGenAlgorithm = {
      algorithm = oid.pkcs1.mgf1,
      parameters = {
        algorithm = oid.sha1,
        parameters = false,
      }
    }

    if value[#fieldIdx]
        and value[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 1) then
      result.maskGenAlgorithm, err = parser:withField(
        value,
        fieldIdx:next(),
        "maskGenAlgorithm",
        parseExplicit,
        parser.parseAlgorithmIdentifier
      )

      if not result.maskGenAlgorithm then
        return nil, err
      end
    end

    result.saltLength = 20

    if value[#fieldIdx]
        and value[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 2) then
      result.saltLength, err = parser:withField(
        value,
        fieldIdx:next(),
        "saltLength",
        parseExplicit,
        parser.parseShortInteger,
        true
      )

      if not result.saltLength then
        return nil, err
      end
    end

    result.trailerField = 1

    if value[#fieldIdx]
        and value[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 3) then
      result.trailerField, err = parser:withField(
        value,
        fieldIdx:next(),
        "trailerField",
        parserExplicit,
        function(parser, trailerField)
          local trailerField, err = parser:parseShortInteger(trailerField, true)

          if not trailerField then
            return nil, err
          end

          if trailerField ~= 1 then
            return nil, parser:makeError(
              errors.x509.invalidTrailerField,
              trailerField
            )
          end

          return trailerField
        end
      )

      if not result.trailerField then
        return nil, err
      end
    end

    return result
  end)

lib.recognizedSignatureAlgorithms[oid.pkcs1.sha1WithRSAEncryption] =
  lib.makeNoOrNullParamSigAlg("sha1WithRSAEncryption")
lib.recognizedSignatureAlgorithms[oid.pkcs1.sha256WithRSAEncryption] =
  lib.makeNoOrNullParamSigAlg("sha256WithRSAEncryption")
lib.recognizedSignatureAlgorithms[oid.pkcs1.sha384WithRSAEncryption] =
  lib.makeNoOrNullParamSigAlg("sha384WithRSAEncryption")
lib.recognizedSignatureAlgorithms[oid.pkcs1.sha512WithRSAEncryption] =
  lib.makeNoOrNullParamSigAlg("sha512WithRSAEncryption")

lib.recognizedSignatureAlgorithms[oid.x25519] = lib.makeNoParamSigAlg("X25519")
lib.recognizedSignatureAlgorithms[oid.edDSA25519] =
  lib.makeNoParamSigAlg("edDSA25519")

return lib

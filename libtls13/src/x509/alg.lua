-- Recognized X.509 certificate algorithms.

local asn = require("tls13.asn")
local errors = require("tls13.error")
local oid = require("tls13.asn.oid")
local util = require("tls13.util")
local utilMap = require("tls13.util.map")

local lib = {}

lib.recognizedAlgorithms = utilMap.makeProjectionMap(tostring)

function lib.makeAlg(name, parser)
  return {
    getName = function()
      return name
    end,

    parseParameters = function(self, p, value, hasSignatureValue)
      return parser(p, value, hasSignatureValue)
    end,
  }
end

function lib.makeNoParamAlg(name)
  return lib.makeAlg(name, function(parser, value)
    if value then
      return nil, parser:makeError(
        errors.x509.algorithmParametersPresent,
        value.TAG
      )
    end

    return false
  end)
end

function lib.makeNullParamAlg(name)
  return lib.makeAlg(name, function(parser, value)
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

function lib.makeNoOrNullParamAlg(name)
  return lib.makeAlg(name, function(parser, value)
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

lib.recognizedAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA256
] = lib.makeNoParamAlg("ecdsa-with-SHA256")
lib.recognizedAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA384
] = lib.makeNoParamAlg("ecdsa-with-SHA384")
lib.recognizedAlgorithms[
  oid.ansiX962.signatures.ecdsaWithSHA2.ecdsaWithSHA512
] = lib.makeNoParamAlg("ecdsa-with-SHA512")

lib.recognizedAlgorithms[oid.ansiX962.keyType.ecPublicKey] =
  lib.makeAlg("ecPublicKey", function(parser, value)
    local result, err = {}
    result.namedCurve, err = parser:parseOid(value)

    if not result.namedCurve then
      return nil, err
    end

    return result
  end)

-- this one neither.
lib.recognizedAlgorithms[oid.pkcs1.rsaEncryption] =
  lib.makeNullParamAlg("rsaEncryption")

local function parseExplicit(parser, value, f, ...)
  local value, err = parser:checkExplicitTag(value)

  if not value then
    return nil, err
  end

  return f(parser, value, ...)
end

lib.recognizedAlgorithms[oid.pkcs1.rsassaPss] =
  lib.makeAlg("RSASSA-PSS", function(parser, value, hasSignatureValue)
    -- RFC4056, §2.2: “When the id-RSASSA-PSS algorithm identifier is used for a
    -- signature, the AlgorithmIdentifier parameters field MUST contain
    -- RSASSA-PSS-params”.
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

lib.recognizedAlgorithms[oid.pkcs1.sha1WithRSAEncryption] =
  lib.makeNoOrNullParamAlg("sha1WithRSAEncryption")
lib.recognizedAlgorithms[oid.pkcs1.sha256WithRSAEncryption] =
  lib.makeNoOrNullParamAlg("sha256WithRSAEncryption")
lib.recognizedAlgorithms[oid.pkcs1.sha384WithRSAEncryption] =
  lib.makeNoOrNullParamAlg("sha384WithRSAEncryption")
lib.recognizedAlgorithms[oid.pkcs1.sha512WithRSAEncryption] =
  lib.makeNoOrNullParamAlg("sha512WithRSAEncryption")

lib.recognizedAlgorithms[oid.x25519] = lib.makeNoParamAlg("X25519")
lib.recognizedAlgorithms[oid.edDSA25519] =
  lib.makeNoParamAlg("edDSA25519")

lib.recognizedAlgorithms[oid.hashalgs.sha256] =
  lib.makeNoOrNullParamAlg("sha-256")
lib.recognizedAlgorithms[oid.hashalgs.sha384] =
  lib.makeNoOrNullParamAlg("sha-384")
lib.recognizedAlgorithms[oid.hashalgs.sha512] =
  lib.makeNoOrNullParamAlg("sha-512")

lib.recognizedAlgorithms[oid.pkcs1.mgf1] =
  lib.makeAlg("pcks1-MGF1", function(parser, value, hasSignatureValue)
    if not value then
      return nil, parser:makeError(errors.x509.algorithmParametersOmitted)
    end

    return parser:parseAlgorithmIdentifier(value)
  end)

return lib

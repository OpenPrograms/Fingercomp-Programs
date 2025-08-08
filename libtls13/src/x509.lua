-- An X.509 certificate parser.

local asn = require("tls13.asn")
local errors = require("tls13.error")
local util = require("tls13.util")
local utilMap = require("tls13.util.map")
local x509Alg = require("tls13.x509.alg")

local lib = {}

-- re-exports
lib.recognizedAttributes = require("tls13.x509.attr").recognizedAttributes
lib.recognizedExtensions = require("tls13.x509.ext").recognizedExtensions
lib.recognizedAlgorithms = x509Alg.recognizedAlgorithms

do
  local meta = {
    __index = {
      pushPath = function(self, label)
        table.insert(self.__path, label)
      end,

      popPath = function(self)
        assert(#self.__path >= 0, "unmatched pop")
        table.remove(self.__path)
      end,

      getPath = function(self)
        return self.__path[#self.__path]
      end,

      renamePathLabel = function(self, newLabel)
        self.__path[#self.__path] = newLabel
      end,

      withPath = function(self, label, f, ...)
        self:pushPath(label)
        local result, err = f(self, ...)
        self:popPath()

        return result, err
      end,

      makeError = function(self, err, ...)
        local context = "top-level"

        if #self.__path > 0 then
          context = table.concat(self.__path, " -> ")
        end

        return err(context, ...)
      end,

      checkField = function(self, obj, key, fieldName)
        if not obj[key] then
          return nil, self:makeError(
            errors.x509.requiredFieldMissing,
            fieldName
          )
        end

        return obj[key]
      end,

      withField = function(self, obj, key, fieldName, f, ...)
        local value, err = self:checkField(obj, key, fieldName)

        if not value then
          return nil, err
        end

        return self:withPath(fieldName, f, value, ...)
      end,

      checkTag = function(self, value, tagSpec)
        if value.TAG ~= tagSpec then
          return nil, self:makeError(
            errors.x509.invalidType,
            value.TAG, tagSpec
          )
        end

        return value
      end,

      checkExplicitTag = function(self, value, outerTagSpec, innerTagSpec)
        if outerTagSpec and value.TAG ~= outerTagSpec then
          return nil, self:makeError(
            errors.x509.invalidType,
            value.TAG, outerTagSpec
          )
        end

        if value.ENCODING ~= "constructed" then
          return nil, self:makeError(
            errors.x509.invalidEncoding,
            value.ENCODING, "constructed"
          )
        end

        if #value ~= 1 then
          return nil, self:makeError(
            errors.x509.invalidType,
            "<unknown>", innerTagSpec or "ANY"
          )
        end

        if innerTagSpec and value[1].TAG ~= innerTagSpec then
          return nil, self:makeError(
            errors.x509.invalidType,
            value[1].TAG, innerTagSpec
          )
        end

        return value[1]
      end,

      checkImplicitTag = function(self, value, innerTagSpec, outerTagSpec)
        if outerTagSpec and value.TAG ~= outerTagSpec then
          return nil, self:makeError(
            errors.x509.invalidType,
            value.TAG, outerTagSpec
          )
        end

        return asn.parseImplicitTag(value, innerTagSpec, self.__path)
      end,

      parse = function(self, cert)
        local tbsCertificate, err =
          self:withField(cert, 1, "tbsCertificate", self.parseTbsCertificate)

        if not tbsCertificate then
          return nil, err
        end

        local signatureAlgorithm, err = self:withField(
          cert, 2, "signatureAlgorithm",
          self.parseSignatureAlgorithm, tbsCertificate
        )

        if not signatureAlgorithm then
          return nil, err
        end

        local signatureValue, err =
          self:withField(cert, 3, "signatureValue", self.parseSignatureValue)

        if not signatureValue then
          return nil, err
        end

        return {
          tbsCertificate = tbsCertificate,
          signatureAlgorithm = signatureAlgorithm,
          signatureValue = signatureValue,
        }
      end,

      parseTbsCertificate = function(self, cert)
        local result, err = {}, nil

        cert, err = self:checkTag(cert, asn.asnTags.universal.sequence)

        if not cert then
          return nil, err
        end

        local fieldIdx = util.makeCounter()
        self.__version = 1

        if cert[fieldIdx:get()].TAG
            == asn.makeTagSpec("contextSpecific", 0) then
          self.__version, err =
            self:withField(cert, fieldIdx:next(), "version", self.parseVersion)

          if not self.__version then
            return nil, err
          end
        end

        result.version = self.__version

        result.serialNumber, err = self:withField(
          cert,
          fieldIdx:next(),
          "serialNumber",
          self.parseSerialNumber
        )

        if not result.serialNumber then
          return nil, err
        end

        result.signature, err = self:withField(
          cert,
          fieldIdx:next(),
          "signature",
          self.parseAlgorithmIdentifier,
          true
        )

        if not result.signature then
          return nil, err
        end

        result.issuer, err =
          self:withField(cert, fieldIdx:next(), "issuer", self.parseIssuer)

        if not result.issuer then
          return nil, err
        end

        result.validity, err =
          self:withField(cert, fieldIdx:next(), "validity", self.parseValidity)

        if not result.validity then
          return nil, err
        end

        result.subject, err =
          self:withField(cert, fieldIdx:next(), "subject", self.parseSubject)

        if not result.subject then
          return nil, err
        end

        result.subjectPublicKeyInfo, err = self:withField(
          cert,
          fieldIdx:next(),
          "subjectPublicKeyInfo",
          self.parseSubjectPublicKeyInfo
        )

        if not result.subjectPublicKeyInfo then
          return nil, err
        end

        result.issuerUniqueId = nil

        if cert[fieldIdx:get()].TAG
            == asn.makeTagSpec("contextSpecific", 1) then
          result.issuerUniqueId, err = self:withField(
            cert,
            fieldIdx:next(),
            "issuerUniqueID",
            self.parseIssuerUniqueId
          )

          if not result.issuerUniqueId then
            return nil, err
          end
        end

        result.subjectUniqueId = nil

        if cert[fieldIdx:get()].TAG
            == asn.makeTagSpec("contextSpecific", 2) then
          result.subjectUniqueId, err = self:withField(
            cert,
            fieldIdx:next(),
            "subjectUniqueID",
            self.parseSubjectUniqueId
          )

          if not result.subjectUniqueId then
            return nil, err
          end
        end

        result.extensions = {}

        if cert[fieldIdx:get()].TAG
            == asn.makeTagSpec("contextSpecific", 3) then
          result.extensions, err = self:withField(
            cert,
            fieldIdx:next(),
            "extensions",
            self.parseExtensions
          )

          if not result.extensions then
            return nil, err
          end
        end

        return result
      end,

      parseSignatureAlgorithm = function(self, sigalg, tbsCertificate)
        local result, err = self:parseAlgorithmIdentifier(sigalg, true)

        if not result then
          return nil, err
        end

        if tbsCertificate.signature.algorithm ~= result.algorithm then
          return nil, self:makeError(
            errors.x509.signatureAlgorithmsDiffer,
            result.algorithm, tbsCertificate.signature.algorithm
          )
        end

        if not x509Alg.areAlgorithmsEqual(tbsCertificate.signature, result) then
          return nil, self:makeError(
            errors.x509.signatureAlgorithmsDiffer.parameters
          )
        end

        return result
      end,

      parseAlgorithmIdentifier = function(self, sigalg, hasSignatureValue)
        local result, err = {}, nil
        sigalg, err = self:checkTag(sigalg, asn.asnTags.universal.sequence)

        if not sigalg then
          return nil, err
        end

        result.algorithm, err =
          self:withField(sigalg, 1, "algorithm", self.parseOid)

        if not result.algorithm then
          return nil, err
        end

        local recognizedAlgorithm = lib.recognizedAlgorithms[result.algorithm]

        if not recognizedAlgorithm then
          return nil, self:makeError(
            errors.x509.unrecognizedAlgorithm,
            result.algorithm
          )
        end

        self:renamePathLabel(("%s: %s"):format(
          self:getPath(),
          recognizedAlgorithm:getName()
        ))

        if sigalg[2] then
          result.parameters, err = self:withField(
            sigalg,
            2,
            "parameters",
            function(parser, params)
              return recognizedAlgorithm:parseParameters(
                parser,
                params,
                hasSignatureValue
              )
            end
          )

          if not result.parameters and err then
            return nil, err
          end
        else
          result.parameters, err = self:withPath("parameters", function(parser)
            return recognizedAlgorithm:parseParameters(
              parser,
              nil,
              hasSignatureValue
            )
          end)

          if result.parameters == nil then
            return nil, err
          end
        end

        return result
      end,

      parseSignatureValue = function(self, sig)
        local sig, err = self:checkTag(sig, asn.asnTags.universal.bitString)

        if not sig then
          return nil, err
        end

        return sig[1]
      end,

      parseVersion = function(self, version)
        local version, err = self:checkExplicitTag(
          version,
          asn.makeTagSpec("contextSpecific", 0),
          asn.asnTags.universal.integer
        )

        if not version then
          return nil, err
        end

        if version.long then
          return nil, self:makeError(errors.x509.unsupportedVersion.unspecified)
        elseif version[1] > 2 or version[1] < 0 then
          return nil, self:makeError(errors.x509.unsupportedVersion, version[1])
        else
          return version[1] + 1
        end
      end,

      parseSerialNumber = function(self, serial)
        local serial, err = self:checkTag(serial, asn.asnTags.universal.integer)

        if not serial then
          return nil, err
        end

        local bytes

        -- negative integers will be weird but whatever
        if not serial.long then
          bytes = (">i8"):pack(serial[1])
        else
          bytes = serial[1]:toBytes()
        end

        return bytes
      end,

      parseIssuer = function(self, issuer)
        return self:parseName(issuer)
      end,

      parseName = function(self, name, allowEmpty)
        return self:withPath("rdnSequence", function()
          local rdns, err = self:checkTag(name, asn.asnTags.universal.sequence)

          if not rdns then
            return nil, err
          end

          if #rdns == 0 and not allowEmpty then
            return nil, self:makeError(errors.x509.nameEmpty)
          end

          local names = {}

          for i, rdn in ipairs(rdns) do
            local rdn, err = self:withPath("#" .. i, function()
              return self:parseRelativeDistinguishedName(rdn)
            end)

            if not rdn then
              return nil, err
            end

            names[i] = rdn
          end

          return names
        end)
      end,

      parseRelativeDistinguishedName = function(self, rdn)
        local rdn, err = self:checkTag(rdn, asn.asnTags.universal.set)

        if not rdn then
          return nil, err
        end

        if #rdn == 0 then
          return nil, self:makeError(errors.x509.nameAttrEmpty)
        end

        local attrs = {}

        for i, attr in ipairs(rdn) do
          local attr, err = self:withPath("attr #" .. i, function()
            return self:parseRdnAttribute(attr)
          end)

          if not attr then
            return nil, err
          end

          table.insert(attrs, attr)
        end

        return attrs
      end,

      parseRdnAttribute = function(self, attr)
        local result, err = {}
        attr, err = self:checkTag(attr, asn.asnTags.universal.sequence)

        result.type, err = self:withField(attr, 1, "type", self.parseOid)

        if not result.type then
          return nil, err
        end

        local recognizedAttribute = lib.recognizedAttributes[result.type]
        self:renamePathLabel(("%s: %s"):format(
          self:getPath(),
          recognizedAttribute and recognizedAttribute:getName() or result.type
        ))

        result.value, err = self:withField(attr, 2, "value", function(_, value)
          if recognizedAttribute then
            return recognizedAttribute:parse(self, value, result.type)
          else
            return self:parseUnrecognizedAttribute(value, result.type)
          end
        end)

        if not result.value then
          return nil, err
        end

        return result
      end,

      parseUnrecognizedAttribute = function(self, value, attrType)
        local dirStr, err = self:parseDirectoryString(value)

        if not dirStr and err == errors.x509.invalidType then
          return value
        elseif not dirStr then
          return nil, err
        else
          return dirStr
        end
      end,

      parseDirectoryString = function(self, value)
        if value.TAG == asn.asnTags.universal.teletexString then
          return self:parseTeletexString(value)
        elseif value.TAG == asn.asnTags.universal.printableString then
          return self:parsePrintableString(value)
        elseif value.TAG == asn.asnTags.universal.universalString then
          return self:parseUniversalString(value)
        elseif value.TAG == asn.asnTags.universal.utf8String then
          return self:parseUtf8String(value)
        elseif value.TAG == asn.asnTags.universal.bmpString then
          return self:parseBmpString(value)
        else
          return self:makeError(
            errors.x509.invalidType,
            value.TAG, "DirectoryString"
          )
        end
      end,

      parseTeletexString = function(self, str)
        local str, err = self:checkTag(str, asn.asnTags.universal.teletexString)

        if not str then
          return nil, err
        end

        -- FIXME: wrong encoding
        return str[1]
      end,

      parsePrintableString = function(self, str)
        local str, err =
          self:checkTag(str, asn.asnTags.universal.printableString)

        if not str then
          return nil, err
        end

        return str[1]
      end,

      parseUniversalString = function(self, str)
        local str, err =
          self:checkTag(str, asn.asnTags.universal.universalString)

        if not str then
          return nil, err
        end

        -- FIXME: wrong encoding
        return str[1]
      end,

      parseUtf8String = function(self, str)
        local str, err = self:checkTag(str, asn.asnTags.universal.utf8String)

        if not str then
          return nil, err
        end

        return str[1]
      end,

      parseBmpString = function(self, str)
        local str, err = self:checkTag(str, asn.asnTags.universal.bmpString)

        if not str then
          return nil, err
        end

        -- FIXME: wrong encoding
        return str[1]
      end,

      parseIa5String = function(self, str)
        local str, err = self:checkTag(str, asn.asnTags.universal.ia5String)

        if not str then
          return nil, err
        end

        return str[1]
      end,

      parseVisibleString = function(self, str)
        local str, err = self:checkTag(str, asn.asnTags.universal.visibleString)

        if not str then
          return nil, err
        end

        return str[1]
      end,

      parseOid = function(self, oid)
        local oid, err =
          self:checkTag(oid, asn.asnTags.universal.objectIdentifier)

        if not oid then
          return nil, err
        end

        return oid[1]
      end,

      parseShortInteger = function(self, int, requireNonNegative)
        local int, err = self:checkTag(int, asn.asnTags.universal.integer)

        if not int then
          return nil, err
        end

        if int.long then
          return nil, self:makeError(errors.x509.valueTooLarge)
        end

        if requireNonNegative and int[1] < 0 then
          return nil, self:makeError(errors.x509.negativeForbidden)
        end

        return int[1]
      end,

      parseValidity = function(self, validity)
        local result, err = {}
        validity, err = self:checkTag(validity, asn.asnTags.universal.sequence)

        if not validity then
          return nil, err
        end

        result.notBefore, err =
          self:withField(validity, 1, "notBefore", self.parseTime)

        if not result.notBefore then
          return nil, err
        end

        result.notAfter, err =
          self:withField(validity, 2, "notAfter", self.parseTime)

        if not result.notAfter then
          return nil, err
        end

        return result
      end,

      parseTime = function(self, time)
        if time.TAG == asn.asnTags.universal.utcTime then
          return self:parseUtcTime(time)
        elseif time.TAG == asn.asnTags.universal.generalizedTime then
          return self:parseGeneralizedTime(time)
        else
          return nil, self:makeError(
            errors.x509.invalidType, time.TAG, "UTCTime or GeneralizedTime"
          )
        end
      end,

      parseUtcTime = function(self, time)
        local year, month, day, hour, minute, second =
          time[1]:match("^(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)Z$")

        if not year then
          return nil, self:makeError(errors.x509.malformedTime)
        end

        year = tonumber(year)
        month = tonumber(month)
        day = tonumber(day)
        hour = tonumber(hour)
        minute = tonumber(minute)
        second = tonumber(second)

        -- whoever came up with this is an unmatched genius
        if year >= 50 then
          year = 1900 + year
        else
          year = 2000 + year
        end

        return self:checkTime(year, month, day, hour, minute, second)
      end,

      parseGeneralizedTime = function(self, time)
        local year, month, day, hour, minute, second =
          time[1]:match("^(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)Z$")

        if not year then
          return nil, self:makeError(errors.x509.malformedTime)
        end

        year = tonumber(year)
        month = tonumber(month)
        day = tonumber(day)
        hour = tonumber(hour)
        minute = tonumber(minute)
        second = tonumber(second)

        return self:checkTime(year, month, day, hour, minute, second)
      end,

      checkTime = function(self, year, month, day, hour, minute, second)
        if year == 0
            or month == 0 or month > 12
            or day == 0 or day > 31 -- yes, Feb 31 passes checks, I'm aware.
            or hour > 23
            or minute > 59
            or second > 60 then -- leap seconds anyone?
          return nil, self:makeError(errors.x509.malformedTime)
        end

        return {
          year = year,
          month = month,
          day = day,
          hour = hour,
          minute = minute,
          second = second,
        }
      end,

      parseSubject = function(self, subject)
        return self:parseName(subject, true)
      end,

      parseSubjectPublicKeyInfo = function(self, pkinfo)
        local result, err = {}
        pkinfo, err =
          self:checkTag(pkinfo, asn.asnTags.universal.sequence)

        if not pkinfo then
          return nil, err
        end

        result.algorithm, err = self:withField(
          pkinfo,
          1,
          "algorithm",
          self.parseAlgorithmIdentifier,
          false
        )

        if not result.algorithm then
          return nil, err
        end

        result.subjectPublicKey, err = self:withField(
          pkinfo,
          2,
          "subjectPublicKey",
          self.parseSubjectPublicKey
        )

        if not result.subjectPublicKey then
          return nil, err
        end

        return result
      end,

      parseSubjectPublicKey = function(self, pubKey)
        local pubKey, err =
          self:checkTag(pubKey, asn.asnTags.universal.bitString)

        if not pubKey then
          return nil, err
        end

        return pubKey[1]
      end,

      parseIssuerUniqueId = function(self, id)
        return self:parseUniqueId(id)
      end,

      parseSubjectUniqueId = function(self, id)
        return self:parseUniqueId(id)
      end,

      parseUniqueId = function(self, id)
        if self.__version < 2 then
          return nil, self:makeError(
            errors.x509.fieldNewVersion,
            2, self.__version
          )
        end

        local id, err =
          self:checkImplicitTag(id, asn.asnTags.universal.bitString)

        if not id then
          return nil, err
        end

        return id[1]
      end,

      parseExtensions = function(self, extensionSeq)
        if self.__version < 3 then
          return nil, self:makeError(
            errors.x509.fieldNewVersion,
            3, self.__version
          )
        end

        local err
        local extensions = utilMap.makeProjectionMap(tostring)
        extensionSeq, err = self:checkExplicitTag(
          extensionSeq,
          asn.makeTagSpec("contextSpecific", 3),
          asn.asnTags.universal.sequence
        )

        if not extensionSeq then
          return nil, err
        end

        if #extensionSeq == 0 then
          return nil, self:makeError(errors.x509.extensionsEmpty)
        end

        for i, extension in ipairs(extensionSeq) do
          local extension, err = self:withPath("#" .. i, function()
            local extension, err = self:parseExtension(extension)

            if extension == nil then
              return nil, err
            elseif extensions[extension.extnID] then
              return nil, self:makeError(errors.x509.duplicateExtension)
            end

            return extension
          end)

          if not extension then
            return nil, err
          end

          extensions[extension.extnID] = extension
        end

        return extensions
      end,

      parseExtension = function(self, ext)
        local fieldIdx = util.makeCounter()
        local result, err = {}
        ext, err = self:checkTag(ext, asn.asnTags.universal.sequence)

        if not ext then
          return nil, err
        end

        result.extnID, err =
          self:withField(ext, fieldIdx:next(), "extnID", self.parseOid)

        if not result.extnID then
          return nil, err
        end

        local recognizedExtension = lib.recognizedExtensions[result.extnID]

        if recognizedExtension then
          self:renamePathLabel(("%s: %s"):format(
            self:getPath(), recognizedExtension:getName()
          ))
        else
          self:renamePathLabel(("%s: %s"):format(
            self:getPath(), result.extnID
          ))
        end

        result.critical = false

        if ext[fieldIdx:get()].TAG == asn.asnTags.universal.boolean then
          result.critical, err = self:withField(
            ext,
            fieldIdx:next(),
            "critical",
            self.parseExtensionCritical
          )

          if result.critical == nil then
            return nil, err
          end
        end

        result.extnValue, err = self:withField(
          ext,
          fieldIdx:next(),
          "extnValue",
          self.parseExtensionValue
        )

        if not result.extnValue then
          return nil, err
        end

        if recognizedExtension then
          result.extnValue, err = self:withPath("extnValue", function()
            if not recognizedExtension.nonDerEncodedValue then
              result.extnValue, err =
                asn.decode(result.extnValue, false, self.__path)

              if not result.extnValue then
                return nil, err
              end
            end

            return recognizedExtension:parse(self, result.extnValue)
          end)

          if result.extnValue == nil then
            return nil, err
          end
        elseif result.critical then
          return nil, self:makeError(errors.x509.unrecognizedCriticalExtension)
        end

        return result
      end,

      parseExtensionCritical = function(self, bool)
        local bool, err = self:checkTag(bool, asn.asnTags.universal.boolean)

        if not bool then
          return nil, err
        end

        return bool[1]
      end,

      parseExtensionValue = function(self, value)
        local value, err =
          self:checkTag(value, asn.asnTags.universal.octetString)

        if not value then
          return nil, err
        end

        return value[1]
      end,
    },
  }

  function lib.parseCertificateFromAsn(certAsn)
    local parser = setmetatable({
      __path = {},
    }, meta)

    return parser:parse(certAsn)
  end
end

return lib

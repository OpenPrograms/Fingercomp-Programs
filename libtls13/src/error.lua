-- The definitions of error objects used throughout the library.

local lib = {}

local acceptedMetas, errorMeta

errorMeta = {
  __tostring = function(self)
    return self.message
  end,

  __len = function(self)
    return #self.message
  end,

  __eq = function(self, other)
    return rawequal(self, other) or
      acceptedMetas[getmetatable(other)] and self.CODE == other.CODE
  end,
}

local errorClassMeta

local function makeError(category, key, summary, fmt)
  return setmetatable({
    CATEGORY = category,
    KEY = key,
    CODE = category .. "." .. key,
    SUMMARY = summary,

    __fmt = fmt,
  }, errorClassMeta)
end

errorClassMeta = {
  __index = {
    copied = function(self, fmt)
      return makeError(self.CATEGORY, self.KEY, self.SUMMARY, fmt)
    end,

    wrapping = function(self, err, ...)
      return setmetatable({
        CATEGORY = self.CATEGORY,
        KEY = self.KEY,
        CODE = self.CODE,
        SUMMARY = self.SUMMARY,

        message = self.__fmt:format(...),
        traceback = debug.traceback(),
        parameters = {...},
        cause = err,
      }, errorMeta)
    end,
  },

  __call = function(self, ...)
    return self:wrapping(nil, ...)
  end,

  __tostring = function(self)
    return self.SUMMARY
  end,

  __eq = function(self, other)
    return rawequal(self, other)
      or acceptedMetas[getmetatable(other)] and self.CODE == other.CODE
  end,
}

acceptedMetas = {
  [errorMeta] = true,
  [errorClassMeta] = true,
}

local function addError(category, key, summary, fmt)
  lib[category] = lib[category] or {}
  lib[category][key] = makeError(category, key, summary, fmt)

  return lib[category][key]
end

addError(
  "parser", "lengthLimitExceeded", "length limit exceeded",
  "%s: length limit specified at byte 0x%x exceeded by %d bytes"
)
addError("parser", "eof", "abrupt end of data", "%s: abrupt end of data")
lib.parser.eof.knownSize = lib.parser.eof:copied(
  "%s: abrupt end of data, expected %d more bytes"
)
lib.parser.eof.knownData = lib.parser.eof:copied(
  "%s: abrupt end of data, expected %s, got %s"
)
addError(
  "parser", "unexpected", "encountered unexpected bytes",
  "%s: expected %s, got %s"
)
lib.parser.unexpected.trailingByte = lib.parser.unexpected:copied(
  "%s: expected end of data, but have %d more bytes"
)
addError(
  "parser", "varintOverlong",
  "varint is encoded with more bytes than necessary",
  "%s: varint is encoded with more bytes than necessary"
)

addError(
  "asn", "reservedLength", "length octet 0xff is reserved",
  "%s: length octet 0xff is reserved"
)
addError(
  "asn", "valueTooLong", "value is too long",
  "%s: value length tag is more than 8 bytes long (%d bytes)"
)
addError(
  "asn", "trailingValueBytes", "contents are smaller than specified length",
  "%s: length %d was specified for contents of length %d"
)
addError(
  "asn", "indefinitePrimitive",
  "indefinite form of length used for primitive encoding",
  "%s: indefinite form of length used for primitive encoding"
)
addError(
  "asn", "derIndefiniteForbidden",
  "indefinite form of length is forbidden by DER",
  "%s: indefinite form of length is forbidden by DER"
)
addError(
  "asn", "derConstructedForbidden",
  "constructed encoding is forbidden by DER",
  "%s: constructed encoding for %s is forbidden by DER"
)
addError(
  "asn", "invalidEncoding", "encoding not supported for type",
  "%s: %s encoding is not supported for this type"
)
addError(
  "asn", "invalidBooleanValue", "invalid boolean value",
  "%s: expected 0x00 or 0xff for boolean, got 0x%02x"
)
addError(
  "asn", "overlongEncoding", "value encoding uses more bytes than necessary",
  "%s: value encoding uses more bytes than necessary"
)
addError(
  "asn", "tooManyUnusedBits", "too many unused bits",
  "%s: number of unused bits (%d) is greater than 7"
)
addError(
  "asn", "nonZeroUnusedBits", "unused bits are non-zero",
  "%s: unused bits are non-zero"
)

addError(
  "x509", "requiredFieldMissing", "required field is missing",
  "%s: required field %s is missing"
)
addError(
  "x509", "invalidType", "value has invalid type",
  "%s: value has invalid type %s, expected %s"
)
addError(
  "x509", "invalidEncoding", "value has invalid encoding",
  "%s: value has invalid encoding %s, expected %s"
)
addError(
  "x509", "unsupportedVersion", "unsupported certificate version",
  "%s: certificate version %s is not supported"
)
lib.x509.unsupportedVersion.unspecified = lib.x509.unsupportedVersion:copied(
  "%s: certificate version is not supported"
)
addError(
  "x509", "fieldNewVersion", "field used from newer version",
  "%s: this field can only be used in version %d and greater, current is %d"
)
addError(
  "x509", "signatureAlgorithmsDiffer",
  "fields signatureAlgorithm and tbsCertificate.signature contain different \z
    algorithm ids",
  "%s: field signatureAlgorithm contains algorithm id %s, \z
    which is different from tbsCertificate.signature's %s"
)
lib.x509.signatureAlgorithmsDiffer.parameters =
  lib.x509.signatureAlgorithmsDiffer:copied(
    "%s: algorithm parameters in field signatureAlgorithm are \z
      different from tbsCertificate.signature's"
  )
addError(
  "x509", "unrecognizedAlgorithm",
  "algorithm is not recognized",
  "%s: algorithm %s is not recognized"
)
addError(
  "x509", "sequenceEmpty", "sequence must not be empty",
  "%s: sequence must not be empty"
)
addError(
  "x509", "nameEmpty", "name is empty",
  "%s: sequence of distinguished names is empty"
)
addError(
  "x509", "nameAttrEmpty", "name attribute list is empty",
  "%s: set of distinguished name attributes is empty"
)
addError(
  "x509", "malformedTime", "time is malformed or has unsupported format",
  "%s: time is malformed or has unsupported format"
)
addError(
  "x509", "extensionsEmpty", "extension sequence is empty",
  "%s: sequence of certificate extensions is empty"
)
addError(
  "x509", "duplicateExtension", "extension is specified twice",
  "%s: extension is specified twice in the certificate"
)
addError(
  "x509", "unrecognizedCriticalExtension",
  "extension marked as critical was not recognized",
  "%s: unrecognized extension was marked critical, \z
    which requires certificate rejection"
)
addError(
  "x509", "keyUsageAllZero", "all bits in keyUsage extension are zero",
  "%s: keyUsage must specify at least one acceptable purpose"
)
addError(
  "x509", "certificatePoliciesEmpty",
  "sequence of certificate policies is empty",
  "%s: sequence of certificate policies is empty"
)
addError(
  "x509", "duplicateCertificatePolicy", "certificate policy is specified twice",
  "%s: certificate policy is specified twice"
)
addError(
  "x509", "policyMappingAnyPolicy", "anyPolicy cannot be mapped",
  "%s: anyPolicy cannot be mapped"
)
addError(
  "x509", "malformedIpAddress", "malformed IP address",
  "%s: IP address must be either 4 or 16 bytes long, but got %d"
)
addError(
  "x509", "valueTooLarge", "value is too large",
  "%s: value is too large"
)
addError(
  "x509", "negativeForbidden", "value must be non-negative",
  "%s: value must be non-negative"
)
addError(
  "x509", "distributionPointUnspecified",
  "distributionPoint and cRLIssuer are both omitted",
  "%s: neither distributionPoint nor cRLIssuer are specified"
)
addError(
  "x509", "algorithmParametersPresent",
  "AlgorithmIdentifier.parameters must be omitted",
  "%s: AlgorithmIdentifier.parameters must be omitted, but got value of type %s"
)
addError(
  "x509", "algorithmParametersOmitted",
  "AlgorithmIdentifier.parameters must be present",
  "%s: AlgorithmIdentifier.parameters must be provided but was omitted"
)
addError(
  "x509", "invalidTrailerField",
  "trailerField must be omitted or set to 1",
  "%s: trailerField must be omitted or set to 1, got %d"
)
addError(
  "x509", "publicKeyInvalid", "public key is malformed",
  "%s: could not decode public key because it was malformed: %s"
)
lib.x509.publicKeyInvalid.subject = lib.x509.publicKeyInvalid:copied(
  "could not decode subject public key because it was malformed: %s"
)

lib.alertEncoding = {}

local function addAlert(num, key, summary, fmt)
  local err = addError("alert", key, summary, fmt)
  err.NUM = num

  lib.alertEncoding[num] = key

  return err
end

addAlert(
  0, "closeNotify", "no more data will be sent on this connection",
  "no more data will be sent on this connection by this peer"
)
addAlert(
  10, "unexpectedMessage", "inappropriate message was received",
  "inappropriate message was received"
)
lib.alert.unexpectedMessage.unknownContentType =
  lib.alert.unexpectedMessage:copied(
    "received record with unknown content type 0x%02x"
  )
lib.alert.unexpectedMessage.noNonZeroByte = lib.alert.unexpectedMessage:copied(
  "deprotected record has no non-zero byte"
)
lib.alert.unexpectedMessage.changeCipherSpec =
  lib.alert.unexpectedMessage:copied(
    "received change_cipher_spec message when it's forbidden"
  )
lib.alert.unexpectedMessage.changeCipherSpecContent =
  lib.alert.unexpectedMessage:copied(
    "change_cipher_spec message must consist only of byte 0x01"
  )
lib.alert.unexpectedMessage.protectedChangeCipherSpec =
  lib.alert.unexpectedMessage:copied(
    "received protected change_cipher_spec message"
  )
lib.alert.unexpectedMessage.unexpectedContentType =
  lib.alert.unexpectedMessage:copied(
    "received unexpected message: expected one of %s, got %s"
  )
lib.alert.unexpectedMessage.unknownHandshakeMessage =
  lib.alert.unexpectedMessage:copied(
    "received unknown handshake message type 0x%02x"
  )
lib.alert.unexpectedMessage.recordSpansKeyChange =
  lib.alert.unexpectedMessage:copied("record spans key change")
addAlert(
  20, "badRecordMac", "record cannot be deprotected",
  "received record that cannot be deprotected"
)
addAlert(
  22, "recordOverflow", "record size limit exceeded",
  "received record that exceeded size limit"
)
lib.alert.recordOverflow.ciphertext = lib.alert.recordOverflow:copied(
  "received record of length %d that exceeded limit (%d)"
)
lib.alert.recordOverflow.plaintext = lib.alert.recordOverflow:copied(
  "received record size after deprotection was %d, which exceeded limit (%d)"
)
addAlert(
  40, "handshakeFailure", "unable to negotiate security parameters",
  "unable to negotiate acceptable set of security parameters"
)
addAlert(
  42, "badCertificate", "certificate was corrupt or failed verification",
  "certificate was corrupt or failed verification"
)
lib.alert.badCertificate.asn = lib.alert.badCertificate:copied(
  "could not decode X.509 certificate: %s"
)
lib.alert.badCertificate.parse = lib.alert.badCertificate:copied(
  "could not parse X.509 certificate: %s"
)
addAlert(
  43, "unsupportedCertificate", "unsupported certificate type",
  "certificate was of unsupported type"
)
addAlert(
  44, "certificateRevoked", "certificate was revoked by its signer",
  "certificate was recoved by its signer"
)
addAlert(
  45, "certificateExpired", "certificate has expired",
  "certificate has expired or is not currently valid"
)
addAlert(
  46, "certificateUnknown", "certificate is unacceptable",
  "unspecified issue arose in processing certificate, \z
    rendering it unacceptable"
)
addAlert(
  47, "illegalParameter", "field in handshake was incorrect",
  "field in handshake was incorrect or inconsistent with other fields"
)
lib.alert.illegalParameter.detail = lib.alert.illegalParameter:copied(
  "field value in handshake message was incorrect: %s"
)
lib.alert.illegalParameter.serverKey = lib.alert.illegalParameter:copied(
  "server key exchange material in key_share extension is malformed: %s"
)
lib.alert.illegalParameter.keyUpdate = lib.alert.illegalParameter:copied(
  "field update_requested of KeyUpdate message has invalid value 0x%02x \z
    (expected 0x01 or 0x02)"
)
lib.alert.illegalParameter.duplicateExtension =
  lib.alert.illegalParameter:copied("extension %s is listed multiple times")
lib.alert.illegalParameter.signatureAlgorithm =
  lib.alert.illegalParameter:copied("unknown signature algorithm 0x%04x")
lib.alert.illegalParameter.selectedVersion = lib.alert.illegalParameter:copied(
  "selected version %d.%d is not 3.4 (corresponding to TLS 1.3)"
)
lib.alert.illegalParameter.cipherSuite = lib.alert.illegalParameter:copied(
  "server-chosen cipher suite %s was not offered"
)
lib.alert.illegalParameter.cipherSuiteUnknown =
  lib.alert.illegalParameter:copied("server chose unknown cipher suite 0x%04x")
lib.alert.illegalParameter.groupAlreadyHasShare =
  lib.alert.illegalParameter:copied(
    "key exchange material for named group %s was already provided by client, \z
      yet server wasn't satisfied with that"
  )
lib.alert.illegalParameter.groupNoShare =
  lib.alert.illegalParameter:copied(
    "server chose named group %s for key exchange despite client not offering \z
      its key exchange material yet"
  )
lib.alert.illegalParameter.cipherSuiteChanged =
  lib.alert.illegalParameter:copied(
    "cipher suite %s selected in ServerHello does not match \z
      cipher suite %s selected previously in HelloRetryRequest"
  )
lib.alert.illegalParameter.namedGroupChanged =
  lib.alert.illegalParameter:copied(
    "named group %s server provided key exchange material for in ServerHello \z
      is different from group %s previously selected in HelloRetryRequest"
  )
lib.alert.illegalParameter.invalidGroupElement =
  lib.alert.illegalParameter:copied("invalid group element for key exchange")
addAlert(
  48, "unknownCa", "unknown certification authority",
  "CA certificate could not be located or could not be matched with known \z
    trust anchor"
)
addAlert(
  49, "accessDenied", "negotiation denied due to access control",
  "decided not to proceed with negotiation after applying access control"
)
addAlert(
  50, "decodeError", "message could not decoded",
  "message could not be decoded because some field was \z
    out of specified range or length of message was incorrect"
)
lib.alert.decodeError.detail = lib.alert.decodeError:copied(
  "message could not be decoded: %s"
)
lib.alert.decodeError.sessionId = lib.alert.decodeError:copied(
  "legacy_session_id size is invalid: expected 0 or 32, got %d"
)
lib.alert.decodeError.compressionMethod = lib.alert.decodeError:copied(
  "server selected non-NULL compression method 0x%02x (illegal in TLS 1.3+)"
)
lib.alert.decodeError.trailingJunk = lib.alert.decodeError:copied(
  "field has trailing junk bytes"
)
lib.alert.decodeError.lengthOutOfRange = lib.alert.decodeError:copied(
  "field length (%d) is out of range"
)
lib.alert.decodeError.messageBoundary = lib.alert.decodeError:copied(
  "received truncated message: %d+ more bytes needed beyond message boundary"
)
lib.alert.decodeError.limitExceeded = lib.alert.decodeError:copied(
  "field contents are larger than its length (%d)"
)
addAlert(
  51, "decryptError", "handshake cryptographic operation failed",
  "handshake cryptographic operation failed"
)
lib.alert.decryptError.publicKey = lib.alert.decryptError:copied(
  "could not decode server public key from certificate: %s"
)
lib.alert.decryptError.verification = lib.alert.decryptError:copied(
  "signature in server CertificateVerify message is invalid"
)
lib.alert.decryptError.finished = lib.alert.decryptError:copied(
  "server Finished message contains invalid verifyData"
)
addAlert(
  70, "protocolVersion", "protocol version is not supported",
  "protocol version is recognized but not supported"
)
lib.alert.protocolVersion.noExtension = lib.alert.protocolVersion:copied(
  "supported_versions extension is missing, implying TLS 1.2- negotiation"
)
addAlert(
  71, "insufficientSecurity", "server requires more secure parameters",
  "server requires parameters more secure that those supported by client"
)
addAlert(
  80, "internalError", "internal error occurred",
  "internal error unrelated to peer or correctness of protocol makes it \z
    impossible to continue"
)
addAlert(
  86, "inapproriateFallback", "invalid connection retry attempt",
  "invalid connection retry attempt from client"
)
addAlert(
  90, "userCanceled", "handshake canceled by user",
  "canceling handshake for reasons unrelated to protocol failure"
)
addAlert(
  109, "missingExtension", "mandatory extension is missing",
  "handshake message does not contain extension mandatory to send"
)
lib.alert.missingExtension.extension = lib.alert.missingExtension:copied(
  "mandatory extension %s was not received"
)
addAlert(
  110, "unsupportedExtension", "unsupported extension",
  "handshake message contains extension known to be prohibited in this \z
    message or not offered by peer"
)
lib.alert.unsupportedExtension.unrecognized =
  lib.alert.unsupportedExtension:copied(
    "received unrecognized extension 0x%04x"
  )
lib.alert.unsupportedExtension.prohibitedMessage =
  lib.alert.unsupportedExtension:copied(
    "received extension %s is prohibited in handshake message %s"
  )
lib.alert.unsupportedExtension.cannotDecode =
  lib.alert.unsupportedExtension:copied(
    "received extension %s that has no registered decoder"
  )
lib.alert.unsupportedExtension.notOffered =
  lib.alert.unsupportedExtension:copied(
    "received extension %s that was not previously offered"
  )
addAlert(
  112, "unrecognizedName", "no server exists identified by provided name",
  "no server exists identified by name provided via server_name extension"
)
addAlert(
  113, "badCertificateStatusResponse",
  "invalid or unacceptable OCSP response is provided by server",
  "invalid or unacceptable OCSP response is provided by server"
)
addAlert(
  115, "unknownPskIdentity", "no acceptable PSK identity is provided",
  "no acceptable PSK identity is provided by client"
)
addAlert(
  116, "certificateRequired", "client certificate is required",
  "client certificate is required but none was provided"
)
addAlert(
  120, "noApplicationProtocol",
  "ALPN extension does not advertise supported protocol",
  "ALPN extension advertises only protocol that server does not support"
)

addError(
  "alert", "unknownAlert", "received unknown alert",
  "received unknown alert (code 0x%02x)"
)

addError(
  "tls", "remoteAlert", "remote peer sent fatal alert",
  "remote peer sent fatal alert: %s"
)
addError(
  "tls", "localAlert", "sent fatal alert to remote peer",
  "sent fatal alert to remote peer: %s"
)
addError(
  "tls", "remoteCloseAlert", "remote peer sent closure alert",
  "remote peer sent closure alert: %s"
)
addError(
  "tls", "localCloseAlert", "sent closure alert to remote peer",
  "sent closure alert to remote peer: %s"
)
addError(
  "tls", "close", "remote peer has closed connection",
  "remote peer has closed connection"
)

return lib

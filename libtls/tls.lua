-- Copyright 2016-2017 Fingercomp

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--     http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local component = require("component")
local comp = require("computer")
local fs = require("filesystem")

local bigint = require("bigint")
local derdecode = require("der-decoder")
local lockbox = require("lockbox")

local base64 = require("lockbox.util.base64")

local advcipher = component.advanced_cipher
local data = component.data
local inet = component.internet

local VERSION = 0x0303

local uuid

do
  local success
  success, uuid = pcall(require, "uuid")
  if not success then
    uuid = require("guid")
  end
end

local function copy(tbl)
  if type(tbl) ~= "table" then return tbl end
  local result = {}
  for k, v in pairs(tbl) do
    result[k] = copy(v)
  end
  return result
end

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function enum(tbl)
  setmetatable(tbl, {
    __index = function(self, k)
      local e, pos = isin(self, k)
      if e then
        return pos
      else
        return nil
      end
    end
  })
  return tbl
end

local function callable2func(callable)
  return function(...)
    return callable(...)
  end
end

local function check(value, arg, ...)
  local types = {...}
  if type(arg) == "number" then
    arg = "#" .. arg
  else
    arg = "`" .. arg .. "`"
  end
  for _, t in pairs(types) do
    ttype = type(value)
    if ttype == t or ttype == "table" and t.__name == t then
      return true
    end
  end
  error("bad value for " .. arg .. ": " .. table.concat(types, " or ") .. ", got " .. tostring(ttype == "table" and t.__name or ttype))
end

local lastProfileTime
local function profile(msg)
  if not lastProfileTime then
    lastProfileTime = comp.uptime()
  else
    local delta = comp.uptime() - lastProfileTime
    print("PROFILER: '" .. msg .. "' took " .. delta .. "s!")
    lastProfileTime = comp.uptime()
  end
end

local TLS_CONTENT_TYPES = enum({
  ChangeCipherSpec = 0x14,
  Alert = 0x15,
  Handshake = 0x16,
  ApplicationData = 0x17
})

local HANDSHAKE_TYPES = enum({
  HelloRequest = 0,
  ClientHello = 1,
  ServerHello = 2,
  Certificate = 11,
  ServerKeyExchange = 12,
  CertificateRequest = 13,
  ServerHelloDone = 14,
  CertificateVerify = 15,
  ClientKeyExchange = 16,
  Finished = 20
})

local hsDecoders = {}

local TLS_VERSION = 0x0303

-- types
local uint8 = ">I1"
local uint16 = ">I2"
local uint24 = ">I3"
local uint32 = ">I4"
local uint64 = ">I8"

-- X.509 OIDs
local x509oid = {
  ["40.6.1.5.5.7"] = "id-pkix",
  ["40.6.1.5.5.7.1"] = "id-pe",
  ["40.6.1.5.5.7.2"] = "id-qt",
  ["40.6.1.5.5.7.3"] = "id-kp",
  ["40.6.1.5.5.7.48"] = "id-ad",
  ["40.6.1.5.5.7.2.1"] = "id-qt-cps",
  ["40.6.1.5.5.7.2.2"] = "id-qt-unotice",
  ["40.6.1.5.5.7.48.1"] = "id-at-ocsp",
  ["40.6.1.5.5.7.48.2"] = "id-at-caIssuers",
  ["40.6.1.5.5.7.48.3"] = "id-at-timeStamping",
  ["40.6.1.5.5.7.48.5"] = "id-at-caRepository",
  ["85.4"] = "id-at",
  ["85.4.41"] = "id-at-name",
  ["85.4.4"] = "id-at-surname",
  ["85.4.42"] = "id-at-givenName",
  ["85.4.43"] = "id-at-initials",
  ["85.4.44"] = "id-at-generationQualifier",
  ["85.4.3"] = "id-at-commonName",
  ["85.4.7"] = "id-at-localityName",
  ["85.4.8"] = "id-at-stateOrProvinceName",
  ["85.4.10"] = "id-at-organizationName",
  ["85.4.11"] = "id-at-organizationalUnitName",
  ["85.4.12"] = "id-at-title",
  ["85.4.46"] = "id-at-dnQualifier",
  ["85.4.6"] = "id-at-countryName",
  ["85.4.5"] = "id-at-serialNumber",
  ["85.4.65"] = "id-at-pseudonym",
  ["9.2342.19200300.100.1.25"] = "id-domainComponent",
  ["42.840.113549.1.9"] = "pkcs-9",
  ["42.840.113549.1.9.1"] = "id-emailAddress",
  ["85.29"] = "id-ce",
  ["85.29.35"] = "id-ce-authorityKeyIdentifier",
  ["85.29.14"] = "id-ce-subjectKeyIdentifier",
  ["85.29.15"] = "id-ce-keyUsage",
  ["85.29.16"] = "id-ce-privateKeyUsagePeriod",
  ["85.29.32"] = "id-ce-certificatePolicies",
  ["85.29.33"] = "id-ce-policyMappings",
  ["85.29.17"] = "id-ce-subjectAltName",
  ["85.29.18"] = "id-ce-issuerAltName",
  ["85.29.9"] = "id-ce-subjectDirectoryAttributes",
  ["85.29.19"] = "id-ce-basicConstraints",
  ["85.29.30"] = "id-ce-nameConstraints",
  ["85.29.36"] = "id-ce-policyConstraints",
  ["85.29.31"] = "id-ce-cRLDistributionPoints",
  ["85.29.37"] = "id-ce-extKeyUsage",
  ["85.29.37.0"] = "anyExtendedKeyUsage",
  ["40.6.1.5.5.7.3.1"] = "id-kp-serverAuth",
  ["40.6.1.5.5.7.3.2"] = "id-kp-clientAuth",
  ["40.6.1.5.5.7.3.3"] = "id-kp-codeSigning",
  ["40.6.1.5.5.7.3.4"] = "id-kp-emailProtection",
  ["40.6.1.5.5.7.3.8"] = "id-kp-timeStamping",
  ["40.6.1.5.5.7.3.9"] = "id-kp-OCSPSigning",
  ["85.29.46"] = "id-ce-freshestCRL",
  ["40.6.1.5.5.7.1.1"] = "id-pe-authorityInfoAccess",
  ["40.6.1.5.5.7.1.11"] = "id-pe-subjectInfoAccess",
  ["85.29.20"] = "id-ce-cRLNumber",
  ["85.29.28"] = "id-ce-issuingDistributionPoint",
  ["85.29.27"] = "id-ce-deltaCRLIndicator",
  ["85.29.21"] = "id-ce-cRLReasons",
  ["85.29.29"] = "id-ce-certificateIssuer",
  ["85.29.23"] = "id-ce-holdInstructionCode",
  ["82.840.10040.2"] = "holdInstruction",
  ["82.840.10040.2.1"] = "id-holdinstruction-none",
  ["82.840.10040.2.2"] = "id-holdinstruction-callissuer",
  ["82.840.10040.2.3"] = "id-holdinstruction-reject",
  ["85.29.24"] = "id-ce-invalidityDate";

  ["42.840.113549.1.1"] = "pkcs-1",
  ["42.840.113549.1.1.1"] = "RSAEncryption",
  ["42.840.113549.1.1.14"] = "sha224WithRSAEncryption",
  ["42.840.113549.1.1.11"] = "sha256WithRSAEncryption",
  ["42.840.113549.1.1.12"] = "sha384WithRSAEncryption",
  ["42.840.113549.1.1.13"] = "sha512WithRSAEncryption",
  ["42.840.113549.1.1.5"] = "sha1WithRSAEncryption"
}

local ALERTS = enum({
  close_notify = 0,
  unexpected_message = 10,
  bad_record_mac = 20,
  decryption_failed_RESERVED = 21,
  record_overflow = 22,
  decompression_failture = 30,
  handshake_failture = 40,
  no_certificate_RESERVED = 41,
  bad_certificate = 42,
  unsupported_certificate = 43,
  certificate_revoked = 44,
  certificate_expired = 45,
  certificate_unknown = 46,
  illegal_parameter = 47,
  unknown_ca = 48,
  access_denied = 49,
  decode_error = 50,
  decrypt_error = 51,
  export_restriction_RESERVED = 60,
  protocol_version = 70,
  insufficient_security = 71,
  internal_error = 80,
  user_canceled = 90,
  no_renegotiation = 100,
  unsupported_extension = 110
})

local function read(ts, len)
  local s = ts[0]
  local result = s:sub(1, len)
  ts[0] = s:sub(len + 1, -1)
  return result
end

local function number2bytes(number)
  if type(number) == "number" then
    local result = ""
    for i = 1, math.ceil(math.ceil(math.log(number, 2)) / 8), 1 do
      local byte = number & 0xff
      result = result .. string.char(byte)
      number = number >> 8
    end
    return result
  elseif type(number) == "table" then
    -- less optimized way:
    -- 1.  convert to hexadecimal array of numbers
    -- 2.  concat
    -- 3.  convert to bytestring
    local hexnum = {}
    local zero = bigint(0)
    repeat
      local mod = number % 16
      table.insert(hexnum, 1, ("%x"):format(tonumber(tostring(mod))))
      number = (number - mod) / 16
    until number == zero
    hexnum = table.concat(hexnum)
    return hexnum:gsub("%x%x", function(n)
      return string.char(tonumber(n, 16))
    end)
  end
end

local function bytes2number(bytes)
  local result = 0
  for i = 1, #bytes, 1 do
    result = (result << 8) | bytes:sub(i, i):byte()
  end
  return result
end

local function getRandom(len)
  return data.random(len)
end

local function strhex2bytes(num)
  return num:gsub("%x%x", function(n)
    return string.char(tonumber(n, 16))
  end)
end

local function getRealTime()
  local tmpname = "/tmp/tls-date-" .. uuid.next()
  local tmp = io.open(tmpname, "w")
  tmp:write("")
  tmp:close()
  local result = fs.lastModified(tmpname)
  fs.remove(tmpname)
  return result
end

local function noPadding()
  return function()
    return nil
  end
end

local function hex(s)
  return s:gsub(".", function(c)
    return ("%02x"):format(c:byte())
  end)
end

local function Alert(fatal, code, description)
  assert(ALERTS[code], "unknown alert: " .. tostring(code))
  return setmetatable({
    fatal = fatal,
    code = code,
    description = description
  }, {
    __index = {
      __name = "Alert"
    }
  })
end

hsDecoders[HANDSHAKE_TYPES.ServerHello] = function(data)
  -- [Version: 2] [Random: 32 = [ [GMT Unix time: 4] [RANDOM: 28] ] ] [Session ID: [Length: 1] ] [Cipher: 2] [Compression: 1] [Extensions: [Length: 2] = [ [Type: 2] [Data: [Length: 2] ] ] ]
  data = {[0] = data}
  local result = {}
  result.tlsVersion = read(data, 2) -- version
  result.random = {}
  result.random.time = uint32:unpack(read(data, 4)) -- GMT Unix time
  result.random.random = read(data, 28) -- random
  len = uint8:unpack(read(data, 1))
  result.sessionid = read(data, len) -- session ID
  result.cipher = read(data, 2) -- cipher
  result.compression = read(data, 1)
  result.extensions = {}
  if #data[0] > 0 then
    len = uint16:unpack(read(data, 2))
    data = {read(data, len)} -- extensions
    while #data[0] ~= 0 do
      local ext = {}
      ext.type = read(data, 2)
      len = uint16:unpack(read(data, 2))
      ext.data = {read(data, len)}
      result.extensions[#result.extensions + 1] = ext
    end
  end
  return result
end

hsDecoders[HANDSHAKE_TYPES.Certificate] = function(data)
  -- [Certificates: [Length: 3] = [ [Certificate 1: [Length: 3] ] [Certificate 2: [Length: 3] ] … ] ]
  data = {[0] = data}
  local result = {}
  len = uint24:unpack(read(data, 3))
  result.certificates = {}
  while #data[0] ~= 0 do
    len = uint24:unpack(read(data, 3))
    local certdata = read(data, len)
    -- X.509 has up to 2 context-specific tags,
    -- and both are sequences.
    local success, certd = pcall(derdecode, certdata, {context = {0x10, 0x10}})
    if not success then
      error(Alert(true, ALERTS.bad_certificate, certd))
    end
    local cert = {}
    cert.certificate = {}
    cert.certificate.version = 0
    if type(certd[1][1]) == "table" then
      cert.certificate.version = certd[1][1][1]
    else
      table.insert(certd[1], 1, {0})
    end
    cert.certificate.serialNumber = certd[1][2]
    cert.certificate.signature = {}
    if not x509oid[table.concat(certd[1][3][1], ".")] then
      error(Alert(true, ALERTS.certificate_unknown, "Unknown signature algorithm: " .. table.concat(certd[1][3][1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues"))
    end
    cert.certificate.signature.algorithm = x509oid[table.concat(certd[1][3][1], ".")]
    cert.certificate.signature.parameters = certd[1][3][2] or {}
    cert.certificate.issuer = {}
    cert.certificate.issuer.rdnSequence = {}
    for k, v in pairs(certd[1][4]) do
      table.insert(cert.certificate.issuer.rdnSequence, {
        type = x509oid[table.concat(v[1][1], '.')],
        value = v[1][2]
      })
    end
    cert.certificate.validity = {}
    cert.certificate.validity.notBefore = certd[1][5][1]
    cert.certificate.validity.notAfter = certd[1][5][2]
    cert.certificate.subject = {}
    cert.certificate.subject.rdnSequence = {}
    for k, v in pairs(certd[1][6]) do
      table.insert(cert.certificate.subject.rdnSequence, {
        type = x509oid[table.concat(v[1][1], '.')],
        value = v[1][2]
      })
    end
    cert.certificate.subjectPublicKeyInfo = {}
    cert.certificate.subjectPublicKeyInfo.algorithm = {}
    if not x509oid[table.concat(certd[1][7][1][1], ".")] then
      error(Alert(true, ALERTS.certificate_unknown, "Unknown signature algorithm: " .. table.concat(certd[1][7][1][1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues"))
    end
    cert.certificate.subjectPublicKeyInfo.algorithm.algorithm = x509oid[table.concat(certd[1][7][1][1], ".")]
    cert.certificate.subjectPublicKeyInfo.algorithm.parameters = certd[1][7][1][2] or {}
    cert.certificate.subjectPublicKeyInfo.subjectPublicKey = certd[1][7][2]
    if cert.certificate.version > 0 and type(certd[1][8]) == "number" then
      cert.certificate.issuerUniqueID = certd[1][8]:tonumber()
    else
      table.insert(certd[1], 8, 0)
    end
    if cert.certificate.version > 0 and type(certd[1][9]) == "number" then
      cert.certificate.issuerUniqueID = certd[1][9]
    else
      table.insert(certd[1], 9, 0)
    end
    cert.certificate.extenstions = {}
    if cert.certificate.version == 2 and certd[1][10] then
      for k, v in pairs(certd[1][10][1]) do
        if #v == 2 then
          table.insert(v, 2, false)
        end
        if not x509oid[table.concat(v[1], ".")] then
          if v[2] then
            error(Alert(v[2], ALERTS.certificate_unknown, "Unknown extension: " .. table.concat(v[1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues"))
          -- else
          --   print("Unknown extension: " .. table.concat(v[1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
          end
        end
        local ext = {
          extnID = x509oid[table.concat(v[1], ".")],
          critical = v[2],
          extnValue = v[3]
        }
      end
    end
    if not x509oid[table.concat(certd[2][1], ".")] then
      error(Alert(true, ALERTS.certificate_unknown, "Unknown signature algorithm: " .. table.concat(certd[2], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues"))
    end
    cert.signatureAlgorithm = {
      algorithm = x509oid[table.concat(certd[2][1], ".")],
      parameters = certd[2][2]
    }
    cert.signatureValue = certd[3]
    result.certificates[#result.certificates + 1] = cert
  end
  return result
end

hsDecoders[HANDSHAKE_TYPES.ServerHelloDone] = function(data)
  -- [Empty]
  -- The body is empty, len is always 0
  return {}
end

local function HMAC(hash, blockLength)
  return function(key, data)
    assert(#key <= blockLength, "Key length must be less than " .. blockLength .. " bytes!")
    local ipad = ("\x36"):rep(blockLength)
    local opad = ("\x5C"):rep(blockLength)
    local paddedKey = key .. ("\x00"):rep(blockLength - #key)
    return hash(number2bytes(bytes2number(key) ~ bytes2number(opad)) .. hash(number2bytes(bytes2number(key) ~ bytes2number(ipad)) .. text))
  end
end

local function P_hash(hashHmac)
  return function(secret, seed, len)
    local seedH = seed
    local result = ""
    for i = 1, math.huge, 1 do
      seedH = hashHmac(secret, seedH)
      result = result .. hashHmac(secret, seedH .. seed)
      if not len or len == #result then
        return result
      elseif len < #result then
        return result:sub(1, len)
      end
    end
  end
end

local function PRF(pHash)
  return function(secret, label, seed, len)
    return pHash(secret, label .. seed, len)
  end
end

local function generateKeyBlock(masterSecret, clientRandom, serverRandom, prf, macKeyLen, keyLen, ivLength)
  local totalLen = keyLen * 2 + macKeyLen * 2 + (ivLength and ivLength * 2 or 0)
  local data = ""
  data = {[0] = prf(masterSecret, "key expansion", serverRandom .. clientRandom, totalLen)}
  return {
    clientWriteMACKey = read(data, macKeyLen),
    serverWriteMACKey = read(data, macKeyLen),
    clientWriteKey = read(data, keyLen),
    serverWriteKey = read(data, keyLen),
    clientWriteIV = ivLength and read(data, ivLength),
    serverWriteIV = ivLength and read(data, ivLength)
  }
end

local function newSequenceNum()
  return {
    read = 0,
    write = 0
  }
end

local function createTLSPlaintext(contentType, data, version, length)
  check(data, "data", "string")
  check(contentType, "contentType", "number")
  check(version, "version", "number", "nil")
  check(length, "length", "number", "nil")
  assert(TLS_CONTENT_TYPES[contentType], "unknown content type")
  assert(contentType == 0x17 or #data ~= 0, "length of non-application data must not be 0")
  local version = version or TLS_VERSION
  local length = length or #data
  -- Prevent modification of struct to prevent screwups
  return setmetatable({}, {
    __index = {
      packet = function(self)
        return uint8:pack(contentType) .. uint16:pack(version) .. uint16:pack(length) .. data
      end,
      contentType = contentType,
      version = version,
      length = length,
      data = data
    },
    __newindex = function(self, k, v)
      error("the struct is read-only")
    end,
    __pairs = function(self)
      return pairs({
        contentType = contentType,
        version = version,
        length = length,
        data = data
      })
    end,
    __ipairs = function(self)
      return ipairs({
        contentType = contentType,
        version = version,
        length = length,
        data = data
      })
    end
  })
end

local function readRecord(s)
  local result = {}
  result.contentType = uint8:unpack(read(s, 1))
  if not TLS_CONTENT_TYPES[result.contentType] then
    error(Alert(true, ALERTS.unexpected_message, "unknown record content type: " .. result.contentType))
  end
  result.version = uint16:unpack(read(s, 2))
  result.length = uint16:unpack(read(s, 2))
  result.data = read(s, result.length)
  return result
end

-- Parses TLS records
local function parseTLSRecords(packets)
  check(packets, "packets", "string")
  local result = {}
  local data = {[0] = packets}
  local prevRecord
  while #data[0] > 0 do
    result[#result+1] = readRecord(data)
  end
  for k, v in pairs(result) do
    result[k] = createTLSPlaintext(v.contentType, v.data, v.version, v.length)
  end
  return result
end

local function concatRecords(records)
  check(records, "records", "table")
  local result = {}
  local prevRecord
  for k, orecord in ipairs(records) do
    local record = {
      contentType = orecord.contentType,
      version = orecord.version,
      length = orecord.length,
      data = orecord.data
    }
    if prevRecord then
      if prevRecord.contentType == orecord.contentType then
        record.length = prevRecord.length + record.length
        record.data = prevRecord.data .. record.data
      else
        result[#result+1] = prevRecord
      end
    end
    prevRecord = record
  end
  result[#result+1] = prevRecord
  for k, v in pairs(result) do
    result[k] = createTLSPlaintext(v.contentType, v.data, v.version, v.length)
  end
  return result
end

local function parseHandshakeMessages(record)
  check(record, "record", "table")
  assert(record.contentType == TLS_CONTENT_TYPES.Handshake, "handshake record expected")
  local data = {[0] = record.data}
  local result = {}
  while #data[0] > 0 do
    local handshakeType = uint8:unpack(read(data, 1))
    if not HANDSHAKE_TYPES[handshakeType] then
      error(Alert(true, ALERTS.unexpected_message, "unknown handshake message type: " .. handshakeType))
    end
    local len = uint24:unpack(read(data, 3))
    local hsData = read(data, len)
    result[#result+1] = {
      handshakeType = handshakeType,
      length = len,
      data = hsData,
      packet = uint8:pack(handshakeType) .. uint24:pack(len) .. hsData
    }
  end
  return result
end

local function createTLSCompressed(tlsPlaintext, compression)
  local contentType, version, length, data = tlsPlaintext.contentType, tlsPlaintext.version, tlsPlaintext.length, tlsPlaintext.data
  if compression == "\x00" then -- No compression
    -- do nothing
  else
    error(Alert(true, ALERTS.decompression_failture, ("unknown compression algorithm: %x"):format(compression:byte())))
  end
  length = #data
  -- Prevent modification of struct to prevent screwups
  return setmetatable({}, {
    __index = {
      packet = function(self)
        return uint8:pack(contentType) .. uint16:pack(version) .. uint16:pack(length) .. data
      end,
      contentType = contentType,
      version = version,
      length = length,
      data = data
    },
    __newindex = function(self, k, v)
      error("the struct is read-only")
    end,
    __pairs = function(self)
      return pairs({
        contentType = contentType,
        version = version,
        length = length,
        data = data
      })
    end,
    __ipairs = function(self)
      return ipairs({
        contentType = contentType,
        version = version,
        length = length,
        data = data
      })
    end
  })
end

-- Only supports block ciphers
local function createCipherMac(args)
  local csuite = args.csuite
  local isBlock = args.isBlock
  local cipherEncrypt = args.cipherEncrypt
  local cipherDecrypt = args.cipherDecrypt
  local mac = args.mac
  local iv = args.iv
  local prf = args.prf
  local keyExchangeCrypt = args.keyExchangeCrypt
  local keyExchangeDecrypt = args.keyExchangeDecrypt
  local ivLength = args.ivLength
  local cipherBlockLength = args.cipherBlockLength
  local macBlockLength = args.macBlockLength
  local keyLength = args.keyLength
  local macKeyLength = args.macKeyLength
  local clientCipherKey = args.clientCipherKey
  local clientMacKey = args.clientMacKey
  local serverCipherKey = args.serverCipherKey
  local serverMacKey = args.serverMacKey
  check(csuite,             "csuite",             "string")
  check(isBlock,            "isBlock",            "boolean")
  check(cipherEncrypt,      "cipherEncrypt",      "function")
  check(cipherDecrypt,      "cipherDecrypt",      "function")
  check(mac,                "mac",                "function")
  check(iv,                 "iv",                 "function")
  check(prf,                "prf",                "function")
  check(keyExchangeCrypt,   "keyExchangeCrypt",   "function")
  check(keyExchangeDecrypt, "keyExchangeDecrypt", "function")
  check(ivLength,           "ivLength",           "number")
  check(cipherBlockLength,  "cipherBlockLength",  "number")
  check(macBlockLength,     "macBlockLength",     "number")
  check(keyLength,          "keyLength",          "number")
  check(macKeyLength,       "macKeyLength",       "number")
  check(clientCipherKey,    "clientCipherKey",    "string", "nil")
  check(clientMacKey,       "clientMacKey",       "string", "nil")
  check(serverCipherKey,    "serverCipherKey",    "string", "nil")
  check(serverMacKey,       "serverMacKey",       "string", "nil")
  if not (clientCipherKey and clientMacKey and serverCipherKey and serverMacKey) and (clientCipherKey or clientMacKey or serverCipherKey or serverMacKey) then
    error("all keys are expected to be provided")
  end
  local setKeys = false
  if clientCipherKey and clientMacKey and serverCipherKey and serverMacKey then
    setKeys = true
  end
  return setmetatable({}, {
    __index = {
      csuite = csuite,
      isBlock = isBlock,
      cipherEncrypt = cipherEncrypt,
      cipherDecrypt = cipherDecrypt,
      mac = mac,
      iv = iv,
      prf = prf,
      keyExchangeCrypt = keyExchangeCrypt,
      keyExchangeDecrypt = keyExchangeDecrypt,
      ivLength = ivLength,
      cipherBlockLength = cipherBlockLength,
      macBlockLength = macBlockLength,
      keyLength = keyLength,
      macKeyLength = macKeyLength,
      clientCipherKey = clientCipherKey,
      clientMacKey = clientMacKey,
      serverCipherKey = serverCipherKey,
      serverMacKey = serverMacKey,
      new = function(self)
        local params = {}
        for k, v in pairs(self) do
          if k ~= "new" then
            params[k] = copy(v)
          end
        end
        return createCipherMac(params)
      end
    },
    __newindex = function(self, k, v)
      error("the struct is read-only")
    end,
    __pairs = function(self)
      return pairs({
        csuite = csuite,
        isBlock = isBlock,
        cipherEncrypt = cipherEncrypt,
        cipherDecrypt = cipherDecrypt,
        mac = mac,
        iv = iv,
        prf = prf,
        keyExchangeCrypt = keyExchangeCrypt,
        keyExchangeDecrypt = keyExchangeDecrypt,
        ivLength = ivLength,
        cipherBlockLength = cipherBlockLength,
        macBlockLength = macBlockLength,
        keyLength = keyLength,
        macKeyLength = macKeyLength,
        clientCipherKey = clientCipherKey,
        clientMacKey = clientMacKey,
        serverCipherKey = serverCipherKey,
        serverMacKey = serverMacKey
      })
    end,
    __ipairs = function(self)
      return ipairs({
        csuite = csuite,
        isBlock = isBlock,
        cipherEncrypt = cipherEncrypt,
        cipherDecrypt = cipherDecrypt,
        mac = mac,
        iv = iv,
        prf = prf,
        keyExchangeCrypt = keyExchangeCrypt,
        keyExchangeDecrypt = keyExchangeDecrypt,
        ivLength = ivLength,
        cipherBlockLength = cipherBlockLength,
        macBlockLength = macBlockLength,
        keyLength = keyLength,
        macKeyLength = macKeyLength,
        clientCipherKey = clientCipherKey,
        clientMacKey = clientMacKey,
        serverCipherKey = serverCipherKey,
        serverMacKey = serverMacKey
      })
    end,
    __call = function(self, clCipherKey, clMacKey, srvCipherKey, srvMacKey)
      if not setKeys then
        check(clCipherKey, "clCipherKey", "string")
        check(clMacKey, "clMacKey", "string")
        check(srvCipherKey, "srvCipherKey", "string")
        check(srvMacKey, "srvMacKey", "string")
        local params = {}
        for k, v in pairs(self) do
          if k ~= "new" then
            params[k] = copy(v)
          end
        end
        params.clientCipherKey = clCipherKey
        params.clientMacKey = clMacKey
        params.serverCipherKey = srvCipherKey
        params.serverMacKey = srvMacKey
        return createCipherMac(params)
      end
      return self
    end
  })
end

local function createTLSCiphertext(tlsCompressed, seqNum, cipherMac)
  local contentType, version, length, data = tlsCompressed.contentType, tlsCompressed.version, tlsCompressed.length, tlsCompressed.data
  local mac = uint64:pack(seqNum.write) .. uint8:pack(contentType) .. uint16:pack(version) .. uint16:pack(length) .. data
  mac = cipherMac.mac(cipherMac.clientMacKey, mac)
  seqNum.write = seqNum.write + 1
  local cipherData = data .. mac
  local iv = cipherMac.iv()
  if cipherMac.isBlock then
    local padding = (#cipherData + 1) % cipherMac.cipherBlockLength
    if padding ~= 0 then
      padding = cipherMac.cipherBlockLength - padding
    end
    cipherData = cipherData .. string.char(padding):rep(padding + 1)
  end
  local encryptedData = iv .. cipherMac.cipherEncrypt(cipherData, cipherMac.clientCipherKey, iv)
  length = #encryptedData
  return setmetatable({}, {
    __index = {
      packet = function(self)
        return uint8:pack(contentType) .. uint16:pack(version) .. uint16:pack(length) .. encryptedData
      end,
      contentType = contentType,
      version = version,
      length = length,
      data = encryptedData
    },
    __newindex = function(self, k, v)
      error("the struct is read-only")
    end,
    __pairs = function(self)
      return pairs({
        contentType = contentType,
        version = version,
        length = length,
        data = encryptedData
      })
    end,
    __ipairs = function(self)
      return ipairs({
        contentType = contentType,
        version = version,
        length = length,
        data = encryptedData
      })
    end
  })
end

local function readTLSCiphertext(record, seqNum, cipherMac, compression)
  local contentType, version, length, encryptedDataWithIV = record.contentType, record.version, record.length, record.data
  local iv = encryptedDataWithIV:sub(1, cipherMac.ivLength)
  local encryptedData = encryptedDataWithIV:sub(cipherMac.ivLength + 1, -1)
  local cipherData, reason = cipherMac.cipherDecrypt(encryptedData, cipherMac.serverCipherKey, iv)
  if not cipherData then
    error(Alert(true, ALERTS.decrypt_error, "could not decrypt TLS record: " .. tostring(reason or "unknown reason")))
  end
  local dataWithMac = cipherData
  local padding
  if cipherMac.isBlock then
    padding = uint8:unpack(cipherData:sub(-1, -1))
    dataWithMac = cipherData:sub(1, -padding - 2)
  end
  local compressedData = dataWithMac:sub(1, -cipherMac.macBlockLength - 1)
  local recordMac
  if cipherMac.macBlockLength ~= 0 then
    recordMac = dataWithMac:sub(-cipherMac.macBlockLength, -1)
  else
    recordMac = ""
  end
  local mac = cipherMac.mac(cipherMac.serverMacKey, uint64:pack(seqNum.read) .. uint8:pack(contentType) .. uint16:pack(version) .. uint16:pack(#compressedData) .. compressedData)
  seqNum.read = seqNum.read + 1
  if mac ~= recordMac then
    error(Alert(true, ALERTS.bad_record_mac, "the given MAC and the computed MAC don't match!"))
  end
  if cipherMac.isBlock then
    if uint8:pack(padding):rep(padding + 1) ~= cipherData:sub(-padding - 1, -1) or #encryptedData % cipherMac.cipherBlockLength ~= 0 then
      error(Alert(true, ALERTS.bad_record_mac, "bad padding!"))
    end
  end
  local data
  if compression == "\x00" then
    data = compressedData
  else
    error(Alert(true, ALERTS.decompression_failture, ("unknown compression type: %x"):format(compression:byte())))
  end
  return createTLSPlaintext(contentType, data)
end

local function createAlert(alert)
  return uint8:pack(alert.fatal and 2 or 1) .. uint8:pack(alert.code)
end

-- Splits the data so that each part's length isn't more than 16383 bytes
local function splitData(contentType,  data)
  local data = {[0] = data}
  local result = {}
  while #data[0] > 0 do
    local fragment = read(data, 2^14 - 1)
    result[#result+1] = createTLSPlaintext(contentType, fragment)
  end
  return result
end

local ciphers = setmetatable({
  TLS_NULL_WITH_NULL_NULL = createCipherMac {
    csuite = "\x00\x00",
    isBlock = false,
    cipherEncrypt = function(data, key, iv)
      return data
    end,
    cipherDecrypt = function(data, key, iv)
      return data
    end,
    mac = function(secret, data)
      return ""
    end,
    iv = function()
      return ""
    end,
    prf = function()
      return ""
    end,
    keyExchangeCrypt = function()
      return ""
    end,
    keyExchangeDecrypt = function()
      return ""
    end,
    ivLength = 0,
    cipherBlockLength = 0,
    macBlockLength = 0,
    keyLength = 0,
    macKeyLength = 0,
    clientCipherKey = "",
    clientMacKey = "",
    serverCipherKey = "",
    serverMacKey = ""
  }
}, {
  __index = function(self, k)
    for i, j in pairs(self) do
      if j.csuite == k or j == k then
        return j
      end
    end
  end
})

do
  local lockbox = require("lockbox")
  lockbox.ALLOW_INSECURE = true

  local stream = require("lockbox.util.stream")
  local array = require("lockbox.util.array")
  local md5digest = require("lockbox.digest.md5")
  local hmac = require("lockbox.mac.hmac")()
  local md5 = function(key, data)
    if data then
      return data.md5(data, key)
    else
      return data.md5(key)
    end
  end
  ciphers.TLS_RSA_WITH_NULL_MD5 = createCipherMac {
    csuite = "\x00\x01",
    isBlock = false,
    cipherEncrypt = function(data)
      return data
    end,
    cipherDecrypt = function(data)
      return data
    end,
    mac = md5,
    iv = function()
      return ""
    end,
    prf = PRF(P_hash(md5)),
    keyExchangeCrypt = callable2func(advcipher.encrypt),
    keyExchangeDecrypt = callable2func(advcipher.decrypt),
    ivLength = 0,
    cipherBlockLength = 0,
    macBlockLength = 16,
    keyLength = 0,
    macKeyLength = 16
  }
end
do
  local stream = require("lockbox.util.stream")
  local array = require("lockbox.util.array")
  local cbcmode = require("lockbox.cipher.mode.cbc")
  local aes128 = require("lockbox.cipher.aes128")

  local sha256 = function(key, hashData)
    if hashData then
      return data.sha256(hashData, key)
    else
      return data.sha256(key)
    end
  end
  local sha256prf = PRF(P_hash(sha256))

  local aes128encrypt = function(data, key, iv)
    local cipher = cbcmode.Cipher()
                          .setKey(array.fromString(key))
                          .setBlockCipher(aes128)
                          .setPadding(noPadding)
    return array.toString(
      cipher.init()
            .update(stream.fromString(iv))
            .update(stream.fromString(data))
            .finish()
            .asBytes())
  end

  local aes128decrypt = function(data, key, iv)
    local decipher = cbcmode.Decipher()
                            .setKey(array.fromString(key))
                            .setBlockCipher(aes128)
                            .setPadding(noPadding)
    return array.toString(
      decipher.init()
              .update(stream.fromString(iv))
              .update(stream.fromString(data))
              .finish()
              .asBytes())
  end

  ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256 = createCipherMac {
    csuite = "\x00\x3c",
    isBlock = true,
    cipherEncrypt = aes128encrypt,
    cipherDecrypt = aes128decrypt,
    mac = sha256,
    iv = function()
      return getRandom(16)
    end,
    prf = sha256prf,
    keyExchangeCrypt = callable2func(advcipher.encrypt),
    keyExchangeDecrypt = callable2func(advcipher.decrypt),
    ivLength = 16,
    cipherBlockLength = 16,
    macBlockLength = 32,
    keyLength = 16,
    macKeyLength = 32
  }
  ciphers.TLS_RSA_WITH_NULL_SHA256 = createCipherMac {
    csuite = "\x00\x3b",
    isBlock = false,
    cipherEncrypt = function(data)
      return data
    end,
    cipherDecrypt = function(data)
      return data
    end,
    mac = sha256,
    iv = function()
      return ""
    end,
    prf = sha256prf,
    keyExchangeCrypt = callable2func(advcipher.encrypt),
    keyExchangeDecrypt = callable2func(advcipher.decrypt),
    ivLength = 0,
    cipherBlockLength = 0,
    macBlockLength = 32,
    keyLength = 0,
    macKeyLength = 32,
    clientCipherKey = "",
    clientMacKey = "",
    serverCipherKey = "",
    serverMacKey = ""
  }
end

-- Stores current cipher
local function newStateManager()
  return setmetatable({
    seqNum = newSequenceNum(),
    read = {
      cipher = ciphers.TLS_NULL_WITH_NULL_NULL,
      compression = "\x00",
    },
    write = {
      cipher = ciphers.TLS_NULL_WITH_NULL_NULL,
      compression = "\x00"
    }
  }, {
    __index = {
      -- Splits data into records, compresses each one, encrypts and returns them
      TLSRecord = function(self, contentType, data)
        local plaintextRecords = splitData(contentType, data)
        local compressedRecords = {}
        for k, record in pairs(plaintextRecords) do
          compressedRecords[k] = createTLSCompressed(record, self.write.compression)
        end
        local encryptedRecords = {}
        for k, record in pairs(compressedRecords) do
          encryptedRecords[k] = createTLSCiphertext(record, self.seqNum, self.write.cipher)
        end
        return encryptedRecords
      end
    }
  })
end

local function createHandshakePacket(code, data)
  assert(HANDSHAKE_TYPES[code], "unknown handshake code")
  return uint8:pack(code) .. uint24:pack(#data) .. data
end

local function packetClientHello(ciphersA, compressionA, extensionsA)
  -- [Version: 2] [Random: 32 = [GMT Unix time: 4] [RANDOM: 28] ] [Session ID: [Length: 1] = [Session ID] ] [Ciphers: [Length: 2] = [ [Cipher 1: 2] [Cipher 2: 2] … ] ] [Compression: [Length: 1] = [ [Method 1: 1] [Method 2: 1] … ] ] [Extensions: [Length: 2] = [ [Extension 1: … = [ [Type: 2] [Data: [Length: 2] ] ] ] ] ]

  -- 1. Random
  local random = ""
  do
    local time = math.floor(getRealTime("%s") / 100) & 0xffffffff
    local rand = getRandom(28)
    random = uint32:pack(time) .. rand
  end

  -- 2. Ciphers
  local ciphers = ""
  do
    local c = ciphersA or {
      "\x00\x2f" -- TLS_RSA_WITH_AES_128_CBC_SHA
    }
    ciphers = uint16:pack(#c * 2) .. table.concat(c)
  end

  -- 3. Compression
  local compression = ""
  do
    local c = compressionA or {
      "\x00" -- No compression
    }
    compression = uint8:pack(#c) .. table.concat(c)
  end

  -- 4. Extensions
  local extensions = ""
  do
    local c = extensionsA or {}
    c["\x00\x0d"] = "\x00\x02\x04\x01" -- signature_algorithms: SHA256 + RSA
    local i = 1
    for k, v in pairs(c) do
      if type(v) == "table" then
        v = table.concat(v)
      end
      c[i] = k .. uint16:pack(#v) .. v
      i = i + 1
    end
    extensions = uint16:pack(#table.concat(c)) .. table.concat(c)
  end

  -- 5. Packet
  local packet = uint16:pack(TLS_VERSION) .. random .. "\x00" .. ciphers .. compression .. extensions
  return createHandshakePacket(HANDSHAKE_TYPES.ClientHello, packet), random
end

local function packetClientCertificate(certificates)
  local packet = ""
  for _, cert in ipairs(certificates) do
    packet = packet .. uint24:pack(#cert) .. cert
  end
  return createHandshakePacket(HANDSHAKE_TYPES.Certificate, uint24:pack(#packet) .. packet)
end

local function packetClientKeyExchange(publicKey, rsaCrypt)
  -- [Encrypted PreMasterSecret: 48]
  local preMasterSecret = {[0] = uint16:pack(TLS_VERSION) .. getRandom(46)}
  local eData64, reason = rsaCrypt(preMasterSecret[0], publicKey)
  if not eData64 then
    error(Alert(true, ALERTS.internal_error, "could not encrypt PMS with the public key: " .. tostring(reason or "unknown reason")))
  end
  local encryptedPreMasterSecret = base64.toString(eData64)
  return createHandshakePacket(HANDSHAKE_TYPES.ClientKeyExchange, uint16:pack(#encryptedPreMasterSecret) .. encryptedPreMasterSecret), preMasterSecret
end

local function generateMasterSecret(preMasterSecret, clientRandom, serverRandom, prf)
  local result = prf(preMasterSecret[0], "master secret", clientRandom .. serverRandom, 48)
  preMasterSecret[0] = nil
  return result
end

local function packetChangeCipherSpec()
  -- [ChangeCipherSpec message: 1]
  return "\x01"
end

local function packetClientFinished(packets, masterSecret, prf, hash)
  -- [Encrypted data]
  -- The data will be encrypted by the state manager,
  -- so we'll create a plaintext record.
  local data = prf(masterSecret, "client finished", hash(table.concat(packets)), 12)
  return createHandshakePacket(HANDSHAKE_TYPES.Finished, data), data
end


-- Makes sure the connection is always properly closed.
-- Also begins a handshake.
local function wrapSocket(sock, extensions)
  local connected, reason = false, nil
  for i = 1, 100, 1 do
    connected, reason = sock.finishConnect()
    if connected then
      break
    end
    os.sleep(.05)
  end
  if not connected then
    error("Could not connect to the server: " .. (reason and tostring(reason) or "unknown reason"))
  end
  local stateMgr = newStateManager()
  local close, alertClose
  local isClosed = false
  local closedByServer = false
  local reads = read
  local timeout = 10 -- the timeout will be unset at the end of handshake
  local readBuffer = ""
  local function setTimeout(to)
    check(to, "to", "number")
    assert(to > 0, "timeout must be a positive number")
    timeout = to
  end
  local function writeRaw(data)
    if isClosed then
      if closedByServer then
        return nil, "closed by the server"
      else
        return nil, "socket is closed"
      end
    end
    local result = {pcall(sock.write, data)}
    if not result[1] then
      close(Alert(true, ALERTS.internal_error))
      error("socket.write error: " .. table.concat(table.pack(table.unpack(result, 2)), ", "))
    end
    return table.unpack(result, 2)
  end
  local function write(contentType, data, noWriteOnClose)
    if isClosed then
      if closedByServer then
        return nil, "closed by the server"
      else
        return nil, "socket is closed"
      end
    end
    local recordResult = {xpcall(stateMgr.TLSRecord, function(m)return m .. debug.traceback()end, stateMgr, contentType, data)}
    if not recordResult[1] then
      pcall(close, Alert(true, ALERTS.internal_error), noWriteOnClose)
      error("an error occured while trying to create records: " .. table.concat(table.pack(table.unpack(recordResult, 2)), ", "))
    end
    local records = recordResult[2]
    for _, record in ipairs(records) do
      writeRaw(record:packet())
    end
  end
  local function readRaw(n)
    if isClosed then
      if closedByServer then
        return nil, "closed by the server"
      else
        return nil, "socket is closed"
      end
    end
    if not ({["number"] = true, ["nil"] = true})[type(n)] then
      return nil, "bad argument #1: number or nil expected"
    end
    local data = ""
    local noDataToReceive = true
    local gotNonNilChunk = false
    if not n then
      local readStartTime = comp.uptime()
      repeat
        local chunk = sock.read(1024)
        if chunk == "" then
          if sock.finishConnect() then -- the connection is still alive
            if gotNonNilChunk then
              noDataToReceive = false
              break
            end
          end
        elseif chunk then
          data = data .. chunk
          gotNonNilChunk = true
          noDataToReceive = false
        end
        os.sleep(.05)
      until not chunk and gotNonNilChunk or not gotNonNilChunk and comp.uptime() - readStartTime > timeout
    else
      gotNonNilChunk = true
      data = sock.read(n)
    end
    if noDataToReceive or not gotNonNilChunk then
      return readBuffer, "recieved nothing"
    end
    readBuffer = readBuffer .. data
    return readBuffer
  end
  local function read(n)
    if type(n) ~= "number" or n <= 0 then
      n = math.huge
    end
    if isClosed then
      if closedByServer then
        return nil, "closed by the server"
      else
        return nil, "socket is closed"
      end
    end
    local success, records
    if #readBuffer >= n * 5 then
      do
        local r
        success, r = pcall(parseTLSRecords, readBuffer)
        if not success then
          if type(r) == "table" and r.__name == "Alert" then
            alertClose(r)
          else
            alertClose(Alert(true, ALERTS.internal_error, "could not parse TLS records: " .. tostring(records or "unknown reason")))
          end
        end
        if #readBuffer >= n * 5 and type(r) == "table" and #r >= n then
          records = r
        end
      end
    end
    if not records then
      local data, reason = readRaw()
      if data and data ~= "" then
        success, records = pcall(parseTLSRecords, data)
        if not success then
          if type(records) == "table" and records.__name == "Alert" then
            alertClose(records)
          else
            alertClose(Alert(true, ALERTS.internal_error, "could not parse TLS records: " .. tostring(records or "unknown reason")))
          end
        end
      elseif data == "" then
        if reason == "recieved nothing" then
          return nil, "timed out"
        end
        close(nil, true)
        error("timed out")
      end
    end
    local storeInBuffer = {}
    for k, record in ipairs(records) do
      if n == 0 then
        storeInBuffer[#storeInBuffer+1] = record.packet()
        records[k] = nil
      else
        n = n - 1
      end
    end
    readBuffer = table.concat(storeInBuffer)
    local decryptedRecords = {}
    for k, record in pairs(records) do
      local result = {pcall(readTLSCiphertext, record, stateMgr.seqNum, stateMgr.read.cipher, stateMgr.read.compression)}
      if not result[1] then
        if type(result[2]) == "table" and result[2].__name == "Alert" then
          alertClose(result[2])
        else
          alertClose(Alert(true, ALERTS.internal_error, "could not decrypt TLS record: " .. tostring(result[2] or "unknown reason")))
        end
      end
      decryptedRecords[k] = result[2]
      records[k] = nil
      os.sleep(.05)
    end
    local resultRecords = concatRecords(decryptedRecords)
    for k, record in ipairs(resultRecords) do
      if record.contentType == TLS_CONTENT_TYPES.Alert then
        local alertData = {[0] = record.data}
        local fatal, code = reads(alertData, 1):byte(), reads(alertData, 1):byte()
        if not fatal or fatal == "" or not code or code == "" then
          close(Alert(true, ALERTS.decode_error))
          error("Could not decode the alert")
        end
        if fatal then
          local alert = Alert(fatal, code)
          close(nil, true)
          if code ~= ALERTS.close_notify then
            error("Fatal alert sent by the server: " .. ALERTS[alert.code])
          else
            close()
            closedByServer = true
          end
        end
      end
      os.sleep(.05)
      return resultRecords
    end
  end
  function close(alert, noWriteOnClose)
    alert = alert or Alert(true, ALERTS.close_notify)
    if not noWriteOnClose then
      write(TLS_CONTENT_TYPES.Alert, createAlert(alert), true)
    end
    sock.close()
    isClosed = true
  end
  function alertClose(alert)
    close(alert)
    error((alert.fatal and "Fatal alert" or "Alert") .. " [" .. alert.code .. "] " .. tostring(alert.description or "no description"))
  end

  local handshakePackets = {}

  -- ClientHello
  local cipherSuites = {}
  for _, v in pairs(ciphers) do
    table.insert(cipherSuites, v.csuite)
  end
  local packet, clientRandom = packetClientHello(cipherSuites, nil, nil, extensions)
  write(TLS_CONTENT_TYPES.Handshake, packet)
  table.insert(handshakePackets, packet)

  -- ServerHello, Certificate, ServerKeyExchange*, CertificateRequest, ServerHelloDone
  -- profile("read1")
  local record, reason = read()
  -- profile("read2")
  if not record then
    close()
    error("Record is nil: " .. tostring(reason or "unknown reason"))
  end
  local serverHello
  if #record > 1 then
    alertClose(Alert(true, ALERTS.unexpected_message, "too many records were recieved"))
  end
  record = record[1]
  if record.contentType ~= TLS_CONTENT_TYPES.Handshake then
    alertClose(Alert(true, ALERTS.unexpected_message, "unexpected message was sent by the server"))
  end
  local success, handshakeMessages = pcall(parseHandshakeMessages, record)
  if not success then
    if type(handshakeMessages) == "table" and handshakeMessages.__name == "Alert" then
      alertClose(handshakeMessages)
    else
      alertClose(Alert(true, ALERTS.internal_error, tostring(handshakeMessages)))
    end
  end
  while handshakeMessages[1].handshakeType == HANDSHAKE_TYPES.HelloRequest do
    -- Ignore HelloRequest messages.
    table.remove(handshakeMessages, 1)
  end
  if handshakeMessages[1].handshakeType ~= HANDSHAKE_TYPES.ServerHello then
    alertClose(Alert(true, ALERTS.unexpected_message, "unexpected handshake message was sent by the server"))
  end
  local result, serverHello = pcall(hsDecoders[handshakeMessages[1].handshakeType], handshakeMessages[1].data)
  if not result then
    if type(serverHello) == "table" and serverHello.__name == "Alert" then
      alertClose(serverHello)
    else
      alertClose(Alert(true, ALERTS.internal_error, tostring(serverHello)))
    end
  end
  table.insert(handshakePackets, handshakeMessages[1].packet)
  table.remove(handshakeMessages, 1)

  local nextCipher = ciphers[serverHello.cipher]
  local nextCompression = serverHello.compression
  if not nextCipher then
    alertClose(Alert(true, ALERTS.handshake_failture, "server requested to use unsupported cipher suite"))
  end

  if handshakeMessages[1].handshakeType ~= HANDSHAKE_TYPES.Certificate then
    alertClose(Alert(true, ALERTS.unexpected_message, "unexpected handshake message was sent by the server"))
  end
  -- profile("beforecert")
  local result, serverCertificate = pcall(hsDecoders[handshakeMessages[1].handshakeType], handshakeMessages[1].data)
  -- profile("aftercert")
  if not result then
    if type(serverCertificate) == "table" and serverCertificate.__name == "Alert" then
      alertClose(serverCertificate)
    else
      alertClose(Alert(true, ALERTS.internal_error, tostring(serverCertificate)))
    end
  end
  table.insert(handshakePackets, handshakeMessages[1].packet)
  table.remove(handshakeMessages, 1)
  if handshakeMessages[1].handshakeType == HANDSHAKE_TYPES.ServerKeyExchange then
    alertClose(Alert(true, ALERTS.unexpected_message, "the server sent ServerKeyExchange message, which isn't legal with RSA"))
  end
  local certificateRequested = false
  if handshakeMessages[1].handshakeType == HANDSHAKE_TYPES.CertificateRequest then
    -- don't parse, as we won't need that data: we aren't gonna send any certificate
    certificateRequested = true
    table.insert(handshakePackets, handshakeMessages[1].packet)
    table.remove(handshakeMessages, 1)
  end
  if handshakeMessages[1].handshakeType ~= HANDSHAKE_TYPES.ServerHelloDone then
    alertClose(Alert(true, ALERTS.unexpected_message, "the server sent unexpected message"))
  end
  local result, serverHelloDone = pcall(hsDecoders[handshakeMessages[1].handshakeType], handshakeMessages[1].data)
  if not result then
    if type(serverHelloDone) == "table" and serverHelloDone.__name == "Alert" then
      alertClose(serverHelloDone)
    else
      alertClose(Alert(true, ALERTS.internal_error, tostring(serverHelloDone)))
    end
  end
  table.insert(handshakePackets, handshakeMessages[1].packet)
  table.remove(handshakeMessages, 1)

  -- profile("2client")

  -- ClientCertificate
  if certificateRequested then
    local clientCertificate = packetClientCertificate({})
    write(TLS_CONTENT_TYPES.Handshake, clientCertificate)
    table.insert(handshakePackets, clientCertificate)
  end
  -- profile("ccertdone")

  -- ClientKeyExchange
  local rsaPublicKey
  if serverCertificate.certificates[1].certificate.subjectPublicKeyInfo.algorithm.algorithm == "RSAEncryption" then
    rsaPublicKey = derdecode(serverCertificate.certificates[1].certificate.subjectPublicKeyInfo.subjectPublicKey)
  else
    alertClose(Alert(true, ALERTS.unsupported_certificate, "unknown public key"))
  end
  -- profile("genkeys")

  rsaPublicKey = {
    base64.fromString("\x00" .. number2bytes(rsaPublicKey[1])), -- javaderp workaround
    base64.fromString("\x00" .. number2bytes(math.floor(tonumber(rsaPublicKey[2]))))
  }

  -- profile("encodekeys")

  local success, clientKeyExchange, preMasterSecret = pcall(packetClientKeyExchange, rsaPublicKey, nextCipher.keyExchangeCrypt)
  -- profile("encrypt")
  if not success then
    if type(clientKeyExchange) == "table" and clientKeyExchange.__name == "Alert" then
      alertClose(clientKeyExchange)
    else
      alertClose(Alert(true, ALERTS.internal_error, "could not create client key exchange message: " .. tostring(clientKeyExchange or "unknown reason")))
    end
  end
  write(TLS_CONTENT_TYPES.Handshake, clientKeyExchange)
  table.insert(handshakePackets, clientKeyExchange)

  -- profile("done")

  --[=[
  do
    -- debug
    local file = io.open("/tlsdebug.log", "a")
    file:write(("PMS_CLIENT_RANDOM %s %s\n"):format(clientRandom:gsub(".",function(c)return("%02x"):format(c:byte())end), preMasterSecret[0]:gsub(".", function(c)return("%02x"):format(c:byte())end)))
    file:close()
  end
  ]=]

  -- CertificateVerify -- omitted

  -- Master secret generation
  local serverRandom = uint32:pack(serverHello.random.time) .. serverHello.random.random
  -- profile("premaster")
  local masterSecret = generateMasterSecret(preMasterSecret, clientRandom, serverRandom, nextCipher.prf)
  -- profile("master")

  --[=[
  do
    -- debug
    local file = io.open("/tlsdebug.log", "a")
    file:write(("CLIENT_RANDOM %s %s\n"):format(clientRandom:gsub(".",function(c)return("%02x"):format(c:byte())end), masterSecret:gsub(".", function(c)return("%02x"):format(c:byte())end)))
    file:close()
  end
  ]=]

  -- Key block
  local keys = generateKeyBlock(masterSecret, clientRandom, serverRandom, nextCipher.prf, nextCipher.macKeyLength, nextCipher.keyLength, nextCipher.ivLength)
  -- profile("keys")

  -- [ChangeCipherSpec]
  -- Updates the state
  write(TLS_CONTENT_TYPES.ChangeCipherSpec, packetChangeCipherSpec())
  nextCipher = nextCipher(keys.clientWriteKey, keys.clientWriteMACKey, keys.serverWriteKey, keys.serverWriteMACKey)
  stateMgr.write.cipher = nextCipher
  stateMgr.write.compression = nextCompression
  stateMgr.seqNum.write = 0

  -- Client Finished
  local clientFinished = packetClientFinished(handshakePackets, masterSecret, nextCipher.prf, nextCipher.mac)
  write(TLS_CONTENT_TYPES.Handshake, clientFinished)
  table.insert(handshakePackets, clientFinished)

  -- profile("cfinished")

  -- [ChangeCipherSpec]
  -- profile("wait")
  local records, reason = read(1)
  if not records then
    alertClose(Alert(true, ALERTS.internal_error, "could not read the data: " .. tostring(reason or "unknown reason")))
  end
  if records[1].contentType ~= TLS_CONTENT_TYPES.ChangeCipherSpec then
    alertClose(Alert(true, ALERTS.unexpected_message, "ChangeCipherSpec message was expected"))
  end
  stateMgr.read.cipher = nextCipher
  stateMgr.read.compression = nextCompression
  stateMgr.seqNum.read = 0

  -- Server Finished
  -- profile("wait")
  local records, reason = read(1)
  if not records then
    alertClose(Alert(true, ALERTS.handshake_failture, "could not read the data: " .. tostring(reason or "unknown reason")))
  end
  if records[1].contentType ~= TLS_CONTENT_TYPES.Handshake then
    alertClose(Alert(true, ALERTS.unexpected_message, "Server Finished message was expected"))
  end
  result, handshakeMessages = pcall(parseHandshakeMessages, records[1])
  if not result then
    if type(handshakeMessages) == "table" and handshakeMessages.__name == "Alert" then
      alertClose(handshakeMessages)
    else
      alertClose(Alert(true, ALERTS.internal_error))
    end
  end
  if handshakeMessages[1].handshakeType ~= HANDSHAKE_TYPES.Finished then
    alertClose(Alert(true, ALERTS.unexpected_message, "Server Finished message was expected"))
  end
  local expectedServerFinished = nextCipher.prf(masterSecret, "server finished", nextCipher.mac(table.concat(handshakePackets)), 12)
  if expectedServerFinished ~= handshakeMessages[1].data then
    alertClose(Alert(true, ALERTS.handshake_failture, "expected server finished isn't equal to the recieved one"))
  end

  -- profile("done")

  for k, v in pairs(handshakeMessages) do
    handshakeMessages[k] = nil
  end

  -- FINALLY, the handshake is over.
  -- Unset the timeout, and return a table of functions.
  timeout = math.huge

  return {
    write = function(data)
      return write(TLS_CONTENT_TYPES.ApplicationData, data)
    end,
    read = function(n)
      local packets, reason = read(n)
      if not packets then
        return packets, reason
      end
      local data = ""
      for _, packet in ipairs(packets) do
        data = data .. packet.data
      end
      return data
    end,
    close = function()
      return close()
    end,
    id = function()
      return sock.id()
    end,
    isClosed = function()
      return (isClosed and not sock.finishConnect()) and true or false
    end,
    finishConnect = function()
      return sock.finishConnect()
    end,
    setTimeout = setTimeout
  }
end

local function newTLSSocket(url, port, ext)
  local socket
  if type(port) == "number" then
    socket = wrapSocket(inet.connect(url, port), ext)
  else
    socket = wrapSocket(inet.connect(url), port)
  end
  return socket
end

return {
  tlsSocket = newTLSSocket,
  wrap = function(sock, ext)
    check(sock, "sock", "table")
    assert(sock.read and sock.write and sock.close and sock.id and sock.finishConnect, "not a socket")
    return wrapSocket(sock, ext)
  end
}

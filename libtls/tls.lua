local component = require("component")

local derdecode = require("der-decoder")
local crypt = require("crypt")

local advcipher = component.advanced_cipher
local data = component.data
local inet = component.internet

local VERSION = 0x0303

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

local TLS_CONTENT_TYPES = enum({
  ChangeCipherSpec = 0x14,
  Alert = 0x15,
  Handshake = 0x16,
  ApplicationData = 0x17
})

local HANDSHAKE_TYPES = enum({
  HelloRequest = 0x00,
  ClientHello = 0x01,
  ServerHello = 0x02,
  Certificate = 0x11,
  ServerHelloDone = 0x0e,
  ClientKeyExchange = 0x10,
  Finished = 0x14
})

local hsDecoders = {}

local TLS_VERSION = 0x0303

-- types
local uint8 = ">I1"
local uint16 = ">I2"
local uint24 = ">I3"
local uint32 = ">I4"

-- X.509 OIDs
local x509oid = {
  ['40.6.1.5.5.7'] = 'id-pkix',
  ['40.6.1.5.5.7.1'] = 'id-pe',
  ['40.6.1.5.5.7.2'] = 'id-qt',
  ['40.6.1.5.5.7.3'] = 'id-kp',
  ['40.6.1.5.5.7.48'] = 'id-ad',
  ['40.6.1.5.5.7.2.1'] = 'id-qt-cps',
  ['40.6.1.5.5.7.2.2'] = 'id-qt-unotice',
  ['40.6.1.5.5.7.48.1'] = 'id-at-ocsp',
  ['40.6.1.5.5.7.48.2'] = 'id-at-caIssuers',
  ['40.6.1.5.5.7.48.3'] = 'id-at-timeStamping',
  ['40.6.1.5.5.7.48.5'] = 'id-at-caRepository',
  ['85.4'] = 'id-at',
  ['85.4.41'] = 'id-at-name',
  ['85.4.4'] = 'id-at-surname',
  ['85.4.42'] = 'id-at-givenName',
  ['85.4.43'] = 'id-at-initials',
  ['85.4.44'] = 'id-at-generationQualifier',
  ['85.4.3'] = 'id-at-commonName',
  ['85.4.7'] = 'id-at-localityName',
  ['85.4.8'] = 'id-at-stateOrProvinceName',
  ['85.4.10'] = 'id-at-organizationName',
  ['85.4.11'] = 'id-at-organizationalUnitName',
  ['85.4.12'] = 'id-at-title',
  ['85.4.46'] = 'id-at-dnQualifier',
  ['85.4.6'] = 'id-at-countryName',
  ['85.4.5'] = 'id-at-serialNumber',
  ['85.4.65'] = 'id-at-pseudonym',
  ['9.2342.19200300.100.1.25'] = 'id-domainComponent',
  ['42.840.113549.1.9'] = 'pkcs-9',
  ['42.840.113549.1.9.1'] = 'id-emailAddress',
  ['85.29'] = 'id-ce',
  ['85.29.35'] = 'id-ce-authorityKeyIdentifier',
  ['85.29.14'] = 'id-ce-subjectKeyIdentifier',
  ['85.29.15'] = 'id-ce-keyUsage',
  ['85.29.16'] = 'id-ce-privateKeyUsagePeriod',
  ['85.29.32'] = 'id-ce-certificatePolicies',
  ['85.29.33'] = 'id-ce-policyMappings',
  ['85.29.17'] = 'id-ce-subjectAltName',
  ['85.29.18'] = 'id-ce-issuerAltName',
  ['85.29.9'] = 'id-ce-subjectDirectoryAttributes',
  ['85.29.19'] = 'id-ce-basicConstraints',
  ['85.29.30'] = 'id-ce-nameConstraints',
  ['85.29.36'] = 'id-ce-policyConstraints',
  ['85.29.31'] = 'id-ce-cRLDistributionPoints',
  ['85.29.37'] = 'id-ce-extKeyUsage',
  ['85.29.37.0'] = 'anyExtendedKeyUsage',
  ['40.6.1.5.5.7.3.1'] = 'id-kp-serverAuth',
  ['40.6.1.5.5.7.3.2'] = 'id-kp-clientAuth',
  ['40.6.1.5.5.7.3.3'] = 'id-kp-codeSigning',
  ['40.6.1.5.5.7.3.4'] = 'id-kp-emailProtection',
  ['40.6.1.5.5.7.3.8'] = 'id-kp-timeStamping',
  ['40.6.1.5.5.7.3.9'] = 'id-kp-OCSPSigning',
  ['85.29.46'] = 'id-ce-freshestCRL',
  ['40.6.1.5.5.7.1.1'] = 'id-pe-authorityInfoAccess',
  ['40.6.1.5.5.7.1.11'] = 'id-pe-subjectInfoAccess',
  ['85.29.20'] = 'id-ce-cRLNumber',
  ['85.29.28'] = 'id-ce-issuingDistributionPoint',
  ['85.29.27'] = 'id-ce-deltaCRLIndicator',
  ['85.29.21'] = 'id-ce-cRLReasons',
  ['85.29.29'] = 'id-ce-certificateIssuer',
  ['85.29.23'] = 'id-ce-holdInstructionCode',
  ['82.840.10040.2'] = 'holdInstruction',
  ['82.840.10040.2.1'] = 'id-holdinstruction-none',
  ['82.840.10040.2.2'] = 'id-holdinstruction-callissuer',
  ['82.840.10040.2.3'] = 'id-holdinstruction-reject',
  ['85.29.24'] = 'id-ce-invalidityDate';

  ['42.840.113549.1.1'] = 'pkcs-1',
  ['42.840.113549.1.1.14'] = 'sha224WithRSAEncryption',
  ['42.840.113549.1.1.11'] = 'sha256WithRSAEncryption',
  ['42.840.113549.1.1.12'] = 'sha384WithRsaEncryption',
  ['42.840.113549.1.1.13'] = 'sha512WithRSAEncryption'
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
  local result = ""
  for i = 1, math.ceil(math.ceil(math.log(number, 2)) / 8), 1 do
    local byte = number & 0xff
    result = result .. string.char(byte)
    number = number >> 8
  end
  return result
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

hsDecoders[HANDSHAKE_TYPES.ServerHello] = function(data)
  -- [Version: 2] [Random: 32 = [ [GMT Unix time: 4] [RANDOM: 28] ] ] [Session ID: [Length: 1] ] [Cipher: 2] [Compression: 1] [Extensions: [Length: 2] = [ [Type: 2] [Data: [Length: 2] ] ] ]
  local result = {}
  result.tlsVersion = read(data, 2) -- version
  result.random = {}
  result.random.time = uint32:unpack(read(data, 4)) -- GMT Unix time
  result.random.random = read(data, 28) -- random
  len = uint24:unpack(read(data, 1))
  result.sessionid = read(data, len) -- session ID
  result.cipher = read(data, 2) -- cipher
  result.compression = read(data, 1)
  result.extensions = {}
  len = uint16:unpack(read(data, 2))
  data = {read(data, len)} -- extensions
  while #data[0] ~= 0 do
    local ext = {}
    ext.type = read(data, 2)
    len = uint16:unpack(read(data, 2))
    ext.data = {read(data, len)}
    result.extensions[#result.extensions + 1] = ext
  end
  return result
end

hsDecoders[HANDSHAKE_TYPES.Certificate] = function(data)
  -- [Certificates: [Length: 3] = [ [Certificate 1: [Length: 3] ] [Certificate 2: [Length: 3] ] … ] ]
  len = uint24:unpack(read(data, 3))
  result.certificates = {}
  while #data[0] ~= 0 do
    len = uint24:unpack(read(data, 3))
    local certdata = read(data, len)
    -- X.509 has up to 2 context-specific tags,
    -- and both are sequences.
    local result, certd = pcall(derdecode, certdata, {context = {0x10, 0x10}})
    if not result then
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
      cert.certificate.issuerUniqueID = certd[1][8]
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
          local pfunc = print
          if v[2] then
            error(Alert(v[2], ALERTS.certificate_unknown, "Unknown extension: " .. table.concat(v[1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues"))
          else
            print("Unknown extension: " .. table.concat(v[1], ".") .. "\nPlease leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
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

local Alert

local function generateKeyBlock(masterSecret, clientRandom, serverRandom, prf, macKeyLen, keyLen, ivLength)
  local totalLen = keyLen * 2 + macKeyLen * 2 + (ivLength and ivLength * 2 or 0)
  local data = ""
  repeat
    data = data .. prf(masterSecret, "key expansion", serverRandom .. clientRandom)
  until #data >= totalLen
  data = {data}
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

local function createTLSPlaintext(contentType, data)
  assert(type(data) == "string", "`data` argument of string type expected")
  assert(type(contentType) == "number", "`contentType` argument of number type expected")
  assert(TLS_CONTENT_TYPES[contentType], "unknown content type")
  assert(contentType == 0x17 or #data ~= 0, "length of non-application data must not be 0")
  local version = TLS_VERSION
  local length = #data
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
  result.length = uint16:unpack(read(s, 2))
  result.fragment = read(s, result.length)
  return result
end

-- Parses TLS records, and concatenates records of the same content type
local function parseTLSRecords(packets)
  assert(type(packets) == "string", "bad value for `packets`: string expected")
  local result = {}
  local data = {[0] = packets}
  local prevRecord
  while #data[0] > 0 do
    local record = readRecord(data)
    if prevRecord then
      if prevRecord.contentType == record.contentType then
        record.length = prevRecord.length + record.length
        record.data = prevRecord.data .. record.data
      else
        result[#result+1] = prevRecord
      end
    end
    prevRecord = record
  end
  result[#result+1] = prevRecord
  return result
end

local function parseHandshakeMessages(record)
  assert(type(record) == "table", "bad value for `record`: table expected")
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
      data = hsData
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
local function createCipherMac(csuite, isBlock, cipherEncrypt, cipherDecrypt, mac, iv, prf, keyExchangeCrypt, keyExchangeDecrypt, ivLen, cipherBlockLength, macBlockLength, keyLength, macKeyLength, clientCipherKey, clientMacKey, serverCipherKey, serverMacKey)
  assert(type(csuite) == "string", "bad value for `csuite`: string expected")
  assert(type(isBlock) == "boolean", "bad value for `isBlock`: boolean expected")
  assert(type(cipherEncrypt) == "function", "bad value for `cipherEncrypt`: function expected")
  assert(type(cipherDecrypt) == "function", "bad value for `cipherDecrypt`: function expected")
  assert(type(mac) == "function", "bad value for `mac`: function expected")
  assert(type(iv) == "function", "bad value for `iv`: function expected")
  assert(type(prf) == "function", "bad value for `prf`: function expected")
  assert(type(keyExchangeCrypt) == "function", "bad value for `keyExchangeCrypt`: function expected")
  assert(type(keyExchangeDecrypt) == "function", "bad value for `keyExchangeDecrypt`: function expected")
  assert(type(ivLen) == "number", "bad value for `ivLen`: number expected")
  assert(type(cipherBlockLength) == "number", "bad value for `cipherBlockLength`: number expected")
  assert(type(macBlockLength) == "number", "bad value for `macBlockLength`: number expected")
  assert(type(keyLength) == "number", "bad value for `keyLength`: number expected")
  assert(type(macKeyLength) == "number", "bad value for `macKeyLength`: number expected")
  assert(({"string", "nil"})[type(clientCipherKey)], "bad value for `clientCipherKey`: string or nil expected")
  assert(({"string", "nil"})[type(clientMacKey)], "bad value for `clientMacKey`: string or nil expected")
  assert(({"string", "nil"})[type(serverCipherKey)], "bad value for `serverCipherKey`: string or nil expected")
  assert(({"string", "nil"})[type(serverMacKey)], "bad value for `serverMacKey`: string or nil expected")
  if not (clientCipherKey and clientMacKey and serverCipherKey and serverMacKey) then
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
      ivLength = ivLen,
      cipherBlockLength = cipherBlockLength,
      macBlockLength = macBlockLength,
      keyLength = keyLength,
      macKeyLength = macKeyLength,
      clientCipherKey = clientCipherKey,
      clientMacKey = clientMacKey,
      serverCipherKey = serverCipherKey,
      serverMacKey = serverMacKey
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
        ivLength = ivLen,
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
        ivLength = ivLen,
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
        assert(type(clCipherKey) == "string", "bad value for `clCipherKey`: string expected")
        assert(type(clMacKey) == "string", "bad value for `clMacKey`: string expected")
        assert(type(srvCipherKey) == "string", "bad value for `srvCipherKey`: string expected")
        assert(type(srvMacKey) == "string", "bad value for `srvMacKey`: string expected")
        clientCipherKey, clientMacKey, serverCipherKey, serverMacKey = clCipherKey, clMacKey, srvCipherKey, srvMacKey
        return self
      end
    end
  })
end

local function createTLSCiphertext(tlsCompressed, seqNum, cipherMac)
  local contentType, version, length, data = tlsCompressed.contentType, tlsCompressed.version, tlsCompressed.length, tlsCompressed.data
  seqNum.write = seqNum.write + 1
  local mac = cipherMac.mac(cipherMac.clientMacKey, number2bytes(seqNum.write) .. uint8:pack(contentType) .. uint16:pack(version) .. data)
  local cipherData = data .. mac
  local iv = cipherMac.ivGen()
  if cipherMac.blockCipher then
    local padding = (#cipheredData + 1) % cipherMac.cipherBlockLength
    cipherData = cipherData .. uint8:pack(padding):rep(padding + 1) .. uint8:pack(padding)
  end
  local encryptedData = iv .. cipherMac.cipherEncrypt(cipherData, cipherMac.clientCipherKey, iv)
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
  local contentType, version, length, encryptedDataWithIV = record.contentType, record.version, record.length, record.fragment
  assert(length <= 2^14 + 2048, Alert(true, ALERTS.record_overflow))
  local iv = encryptedDataWithIV:sub(1, cipherMac.ivLength)
  local encryptedData = encryptedDataWithIV:sub(cipherMac.ivLength + 1, -1)
  local cipherData = cipherMac.cipherDecrypt(encryptedData, cipherMac.serverCipherKey, iv)
  local dataWithMac = cipherData
  local padding
  if cipherMac.isBlock then
    padding = cipherData:sub(-1, -1)
    dataWithMac = cipherData:sub(1, -uint8:unpack(padding) - 1)
  end
  local compressedData = dataWithMac:sub(1, -cipherMac.macBlockLength - 1)
  assert(#cipherData <= 2^14 + 1024, Alert(true, ALERTS.record_overflow))
  local recordMac = dataWithMac:sub(-cipherMac.macBlockLength, -1)
  seqNum.read = seqNum.read + 1
  local mac = cipherMac.mac(cipherMac.serverMacKey, number2bytes(seqNum.read) .. uint8:pack(contentType) .. uint16:pack(version) .. data)
  if mac ~= recordMac then
    error(Alert(true, ALERTS.bad_record_mac, "the given MAC and the computed MAC don't match!"))
  end
  if cipherMac.isBlock then
    if dataWithMac:sub(-uint8:unpack(padding) - 1, -2) ~= padding:rep(uint8:unpack(padding)) or #cipherData % cipherMac.cipherBlockLength then
      error(Alert(true, ALERTS.bad_record_mac, "bad padding!"))
    end
  end
  local data
  if compression == "\x00" then
    data = compressedData
  else
    error(Alert(true, ALERTS.decompression_failture, ("unknown compression type: %x"):format(compression:byte())))
  end
  assert(#data <= 2^14 - 1, Alert(true, ALERTS.record_overflow))
  return createTLSPlaintext(contentType, version, length, data)
end

function Alert(fatal, code, description)
  assert(ALERTS[code], "unknown alert")
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
  TLS_NULL_WITH_NULL_NULL = createCipherMac(
    "\x00\x00", -- csuite
    false -- isBlock
    function(data, key, iv) -- cipherEncrypt
      return data
    end,
    function(data, key, iv) -- cipherDecrypt
      return data
    end,
    function(secret, data) -- mac
      return ""
    end,
    function() -- iv
      return ""
    end,
    function() -- PRF
      return ""
    end,
    function() -- keyExchangeCrypt
      return ""
    end,
    function() -- keyExchangeDecrypt
      return ""
    end,
    0, -- ivLen
    0, -- cipherBlockLength
    0, -- macBlockLength
    0, -- keyLength
    0, -- macKeyLength
    "", -- cipherKey
    "" -- macKey
  ),
  TLS_RSA_WITH_NULL_MD5 = createCipherMac(
    "\x00\x01", -- csuite
    false, -- isBlock
    function(data) -- cipherEncrypt
      return data
    end,
    function(data) -- cipherDecrypt
      return data
    end,
    data.md5, -- mac
    function() -- iv
      return ""
    end,
    PRF(P_hash(data.md5)), -- PRF
    advcipher.encrypt, -- keyExchangeCrypt
    advcipher.decrypt, -- keyExchangeDecrypt
    0, -- ivLen
    0, -- cipherBlockLength
    16, -- macBlockLength
    0, -- keyLength
    16, -- macKeyLength
  )
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
  local sha256hmac = HMAC(crypt.hash.sha256, 64)
  local sha256phash = P_hash(sha256hmac)
  local sha256prf = PRF(sha256phash)
  ciphers.TLS_RSA_WITH_AES_128_CBC_SHA256 = createCipherMac(
    "\x00\x3c", -- csuite
    true, -- isBlock
    data.encrypt, -- cipherEncrypt
    data.decrypt, -- cipherDecrypt
    sha256hmac, -- mac
    function() -- iv
      return getRandom(16)
    end,
    sha256prf, -- PRF
    advcipher.encrypt, -- keyExchangeCrypt
    advcipher.decrypt, -- keyExchangeDecrypt
    16, -- ivLen
    16, -- cipherBlockLength
    32, -- macBlockLength
    16, -- keyLength
    32 -- macKeyLength
  )
  ciphers.TLS_RSA_WITH_NULL_SHA256 = createCipherMac(
    "\x00\x3b", -- csuite
    false, -- isBlock
    function(data) -- cipherEncrypt
      return data
    end,
    function(data) -- cipherDecrypt
      return data
    end,
    sha256hmac, -- mac
    function() -- iv
      return ""
    end,
    sha256prf, -- PRF
    advcipher.encrypt, -- keyExchangeCrypt
    advcipher.decrypt, -- keyExchangeDecrypt
    0, -- ivLen
    0, -- cipherBlockLength
    32, -- macBlockLength
    0, -- keyLength
    32, -- macKeyLength
    "", -- cipherKey
    "", -- macKey
  )
end

-- Stores current cipher
local function newStateManager()
  return setmetatable({
    cipher = ciphers.TLS_NULL_WITH_NULL_NULL,
    compression = "\x00",
    seqNum = newSequenceNum()
  }, {
    __index = {
      -- Splits data into records, compresses each one, encrypts and returns them
      TLSRecord = function(self, contentType, data)
        local plaintextRecords = splitData(contentType, data)
        local compressedRecords = {}
        for k, record in pairs(plaintextRecords) do
          compressedRecords[k] = createTLSCompressed(record, self.compression)
          plaintextRecords[k] = nil
        end
        local encryptedRecords = {}
        for k, record in pairs(compressedRecords) do
          encryptedRecords[k] = createTLSCiphertext(record, self.seqNum, self.cipher)
          compressedRecords[k] = nil
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
    local time = getRealTime("%s")
    local rand = genRandom(28)
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
    compression = uint8:pack(#c * 2) .. table.concat(c)
  end

  -- 4. Extensions
  local extensions = ""
  do
    local c = extensionsA or {
      {"\x00\x0d", "\x00\x02\x06\x01"} -- signature_algorithms: SHA512 + RSA
    }
    for i, j in pairs(c) do
      c[i] = table.concat(j)
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
  local encryptedPreMasterSecret = rsaCrypt(preMasterSecret[0], publicKey)
  return createHandshakePacket(HANDSHAKE_TYPES.ClientKeyExchange, encryptedPreMasterSecret), {[0] = preMasterSecret}
end

local function generateMasterSecret(preMasterSecret, clientRandom, serverRandom, prf)
  local result = prf(preMasterSecret[0], "master secret", clientRandom .. serverRandom)
  preMasterSecret[0] = nil
  return result
end

local function packetChangeCipherSpec()
  -- [ChangeCipherSpec message: 1]
  return "\x01"
end

local function packetClientFinished(packets, masterSecret, prf, hashHMAC)
  -- [Encrypted data]
  -- The data will be encrypted by the state manager,
  -- so we'll create a plaintext record.
  local data = prf(masterSecret, "client finished", hashHMAC(table.concat(packets)))
  return createHandshakePacket(HANDSHAKE_TYPES.Finished, data), data
end

local function alertClose(close, alert)
  close(alert)
  error((alert.fatal and "Fatal alert" or "Alert") .. " [" .. alert.code .. "] " .. (alert.description or "no description"))
end

-- Makes sure the connection is always properly closed.
-- Also begins a handshake.
local function wrapSocket(sock)
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
  local close
  local isClosed = false
  local function writeRaw(data)
    if isClosed then
      return nil, "socket is closed"
    end
    local result = {pcall(sock.write, data)}
    if not result[1] then
      close(Alert(true, ALERTS.internal_error))
      error("socket.write error: " .. table.concat(table.pack(table.unpack(result, 2)), ", "))
    end
    return table.unpack(result, 2)
  end
  local function write(contentType, data)
    if isClosed then
      return nil, "socket is closed"
    end
    local recordResult = {pcall(stateMgr.TLSRecord, stateMgr, contentType, data)}
    if not recordResult[1] then
      close(Alert(true, ALERTS.internal_error))
      error("an error occured while trying to create records: " .. table.concat(table.pack(table.unpack(recordResult, 2)), ", "))
    end
    for _, record in ipairs(records) do
      writeRaw(record.packet())
    end
  end
  local function readRaw(n)
    if isClosed then
      return nil, "socket is closed"
    end
    if not ({"number", "nil"})[type(n)] then
      return nil, "bad argument #1: number or nil expected"
    end
    if n then
      local data = ""
      repeat
        local chunk = sock.read()
        if chunk then
          data = data .. chunk
        end
      until not chunk
      return data
    end
    return sock.read(n)
  end
  local function read()
    if isClosed then
      return nil, "socket is closed"
    end
    local data = readRaw()
    if data and data ~= "" then
      local records = parseTLSRecords(data)
      local decryptedRecords = {}
      for k, record in pairs(records) do
        local result = {pcall(readTLSCiphertext, record, stateMgr.seqNum, stateMgr.cipher, stateMgr.compression)}
        if not result[1] then
          if result[2].__name == "Alert" then
            alertClose(result[2])
          end
        end
        decryptedRecords[k] = result[2]
        if result[2].contentType == TLS_CONTENT_TYPES.Alert then
          local alertData = {[0] = result[2].data}
          local fatal, code = read(alertData, 1), read(alertData, 1)
          if not fatal or fatal == "" or not code or code == "" then
            close(Alert(true, ALERTS.decode_error))
            error("Could not decode the alert")
          end
          if fatal then
            close(Alert(fatal, code))
            if code ~= ALERTS.close_notify then
              error("Fatal alert sent by the server: " .. ALERTS[result[2].code])
            else
              return nil, "closed by the server"
            end
          end
        end
        records[k] = nil
      end
      return decryptedRecords
    end
  end
  local function close(alert)
    alert = alert or Alert(true, ALERTS.close_notify)
    write(TLS_CONTENT_TYPES.Alert, createAlert(alert))
    socket.close()
    isClosed = true
  end

  local handshakePackets = {}

  -- ClientHello
  local cipherSuites = {}
  for _, v in pairs(ciphers) do
    table.insert(cipherSuites, v.csuite)
  end
  local packet, clientRandom = packetClientHello(cipherSuites)
  write(TLS_CONTENT_TYPES.Handshake, packet)
  table.insert(handshakePackets, packet)

  -- ServerHello, Certificate, ServerKeyExchange*, CertificateRequest, ServerHelloDone
  local record = read()
  local serverHello
  if #record > 1 then
    alertClose(Alert(true, ALERTS.unexpected_message, "too many records were recieved"))
  end
  record = record[1]
  if record.contentType ~= TLS_CONTENT_TYPES.Handshake then
    alertClose(Alert(true, ALERTS.unexpected_message, "unexpected message was sent by the server"))
  end
  local handshakeMessages = parseHandshakeMessages(record)
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
  table.insert(handshakePackets, handshakeMessages[1].data)
  table.remove(handshakeMessages, 1)
  local nextCipher = ciphers[serverHello.cipher]
  local nextCompression = serverHello.compression
  if handshakeMessages[1].handshakeType ~= HANDSHAKE_TYPES.Certificate then
    alertClose(Alert(true, ALERTS.unexpected_message, "unexpected handshake message was sent by the server"))
  end
  local result, serverCertificate = pcall(hsDecoders[handshakeMessages[1].handshakeType], handshakeMessages[1].data)
  if not result then
    if type(serverCertificate) == "table" and serverCertificate.__name == "Alert" then
      alertClose(serverCertificate)
    else
      alertClose(Alert(true, ALERTS.internal_error, tostring(serverCertificate)))
    end
  end
  table.insert(handshakePackets, handshakeMessages[1].data)
  table.remove(handshakeMessages, 1)
  if handshakeMessages[1].handshakeType == HANDSHAKE_TYPES.ServerKeyExchange then
    alertClose(Alert(true, ALERTS.unexpected_message, "the server sent ServerKeyExchange message, which isn't legal with RSA"))
  end
  local certificateRequested = false
  if handshakeMessages[1].handshakeType == HANDSHAKE_TYPES.CertificateRequest then
    -- don't parse, as we won't need that data: we aren't gonna send any certificate
    certificateRequested = true
    table.insert(handshakePackets, handshakeMessages[1].data)
    table.remove(handshakeMessage, 1)
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

  -- ClientCertificate
  if certificateRequested then
    local clientCertificate = packetClientCertificate({})
    write(TLS_CONTENT_TYPES.Handshake, clientCertificate)
    table.insert(handshakePackets, clientCertificate)
  end

  -- ClientKeyExchange
  local clientKeyExchange, preMasterSecret = packetClientKeyExchange(serverCertificate[1].certificate.subjectPublicKeyInfo.subjectPublicKey, rsaCrypt)
  write(TLS_CONTENT_TYPES.Handshake, clientKeyExchange)
  table.insert(handshakePackets, clientKeyExchange)

  -- CertificateVerify -- omitted

  -- Master secret generation
  local serverRandom = uint32:pack(serverHello.random.time) .. serverHello.random.random
  local masterSecret = generateMasterSecret(preMasterSecret, clientRandom, serverRandom, prf)

  local cipherRsaAesSha = "TLS_RSA_WITH_AES_128_CBC_SHA"

  -- Key block
  local keys = generateKeyBlock(masterSecret, clientRandom, serverRandom, prf, nextCipher.macKeyLength, nextCipher.keyLength, nextCipher.ivLength)

  -- [ChangeCipherSpec]
  -- Updates the state
  write(TLS_CONTENT_TYPES.ChangeCipherSpec, packetChangeCipherSpec())
  stateMgr.cipher = nextCipher(keys.clientWriteKey, keys.clientWriteMACKey, keys.serverWriteKey, keys.serverWriteMACKey)
  stateMgr.compression = compression

  -- Client Finished
  local clientFinished = packetClientFinished(handshakePackets, masterSecret, prf, hashHMAC)
  write(TLS_CONTENT_TYPES.Handshake, clientFinished)
  table.insert(handshakePackets, clientFinished)

  -- [ChangeCipherSpec]
  local records = read()
  if records[1].contentType ~= TLS_CONTENT_TYPES.ChangeCipherSpec then
    alertClose(Alert(true, ALERTS.unexpected_message, "ChangeCipherSpec message was expected"))
  end

  -- Server Finished
  if records[2].contentType ~= TLS_CONTENT_TYPES.Handshake then
    alertClose(Alert(true, ALERTS.unexpected_message, "Server Finished message was expected"))
  end
  result, handshakeMessages = pcall(parseHandshakeMessages, records[2])
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
  local _, expectedServerFinished = packetClientFinished(handshakePackets, masterSecret, prf, hashHMAC)
  if expectedServerFinished ~= handshakeMessages[1].data then
    alertClose(Alert(true, ALERTS.handshake_failture, "expected server finished isn't equal to the recieved one"))
  end

  -- FINALLY, the handshake is over.
  -- Return a table of functions.
  return {
    write = function(data)
      return write(TLS_CONTENT_TYPES.ApplicationData, data)
    end,
    read = function()
      local packets = read()
      local data = ""
      for _, packet in ipairs(packets) do
        data = data .. packet.data
      end
      return data
    end,
    close = function()
      close()
    end,
    id = function()
      return sock.id()
    end
  }
end

local function newTLSSocket(url)
  local socket = wrapSocket(inet.connect(url))
  return socket
end

return {
  tlsSocket = newTLSSocket
}

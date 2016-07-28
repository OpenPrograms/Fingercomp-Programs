local derdecode = require("der-decoder")

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
    if v = value then
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
  ClientHello = 0x01,
  ServerHello = 0x02,
  ServerCertificate = 0x11,
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

local function packageClientHello(ciphersA, compressionA, extensionsA)
  -- [HANDSHAKE_CODE: 1] [TLS version: 2] [Body: [Length: 2] = [ [Handshake message type: 1] [Handshake message: [Length: 3] = [ [Version: 2] [Random: 32 = [GMT Unix time: 4] [RANDOM: 28] ] [Session ID: [Length: 1] = [Session ID] ] [Ciphers: [Length: 2] = [ [Cipher 1: 2] [Cipher 2: 2] … ] ] [Compression: [Length: 1] = [ [Method 1: 1] [Method 2: 1] … ] ] [Extensions: [Length: 2] = [ [Extension 1: … = [ [Type: 2] [Data: [Length: 2] ] ] ] ] ] ] ] ] ]

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
  packet = uint8:pack(HANDSHAKE_TYPES.ClientHello) .. uint24:pack(#packet) .. packet
  return uint8:pack(HANDSHAKE_CODE) .. uint16:pack(TLS_VERSION) .. uint16:pack(#packet) .. packet, random
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

hsDecoders[HANDSHAKE_TYPES.ServerCertificate] = function(data)
  -- [Certificates: [Length: 3] = [ [Certificate 1: [Length: 3] ] [Certificate 2: [Length: 3] ] … ] ]
  len = uint24:unpack(read(data, 3))
  result.certificates = {}
  while #data[0] ~= 0 do
    len = uint24:unpack(read(data, 3))
    local certdata = read(data, len)
    -- X.509 has up to 2 context-specific tags,
    -- and both are sequences.
    local certd = derdecode(certdata, {context = {0x10, 0x10}})
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
      error("Unknown signature algorithm: " .. table.concat(certd[1][3][1], "."))
      print("Please leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
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
      error("Unknown signature algorithm: " .. table.concat(certd[1][7][1][1], "."))
      print("Please leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
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
            pfunc = error
          end
          pfunc("Unknown extension: " .. table.concat(v[1], "."))
          print("Please leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
        end
        local ext = {
          extnID = x509oid[table.concat(v[1], ".")],
          critical = v[2],
          extnValue = v[3]
        }
      end
    end
    if not x509oid[table.concat(certd[2][1], ".")] then
      error("Unknown signature algorithm: " .. table.concat(certd[2], "."))
      print("Please leave an issue at https://github.com/OpenPrograms/Fingercomp-Programs/issues")
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

local function parseServerHelloDone(data)
  -- [Empty]
  -- The body is empty, len is always 0
  return {}
end

local function packetClientKeyExchange(packet, publicKey)
  -- [HANDSHAKE code: 1] [TLS version: 2] [Body: [Length: 2] = [ [Handshake message type: 1] [Handshake message: [Length: 3] = [Encrypted PreMasterSecret: 48] ] ] ]
  local preMasterSecret = {[0] = uint16:pack(TLS_VERSION) .. getRandom(46)}
  local encryptedPreMasterSecret = encryptRSA(preMasterSecret[0], publicKey)
  local result = uint8:pack(HANDSHAKE_TYPES.ClientKeyExchange) .. uint24:pack(#encryptedPreMasterSecret) .. encryptedPreMasterSecret
  return uint8:pack(HANDSHAKE_CODE) .. uint16:pack(TLS_VERSION) .. uint16:pack(#result) .. result, {
    preMasterSecret = preMasterSecret
  }
end

local function generateMasterSecret(preMasterSecret, clientRandom, serverRandom, prf)
  local result = prf(preMasterSecret[0], "master secret", clientRandom .. serverRandom)
  preMasterSecret[0] = nil
  return result
end

local function packetChangeCipherSpec()
  -- [ChangeCipherSpec code: 1] [TLS version: 2] [Body: [Length: 2] = [ [ChangeCipherSpec message: 1] ] ]
  return uint8:pack(CHANGE_CIPHER_SPEC_CODE) .. uint16:pack(TLS_VERSION) .. "\x00\x01\x01"
end

local function packetClientFinished(packets, masterSecret, prf, hashHMAC)
  -- [HANDSHAKE code: 1] [TLS version: 2] [Body: [Length: 2] = [ [Handshake message type: 1] [Handshake message: [Length: 3] = [Encrypted data] ] ] ]
  local data = prf(masterSecret, "client finished", hashHMAC(table.concat(packets)))
  local result = uint8:pack(HANDSHAKE_TYPES.Finished) .. uint24:pack(#data) .. data
  return uint8:pack(HANDSHAKE_CODE) .. uint16:pack(TLS_VERSION) .. uint16:pack(#result) .. result
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
  assert(TLS_CONTENT_TYPES[result.contentType], "unknown record content type: " .. result.contentType)
  result.length = uint16:unpack(read(s, 2))
  result.fragment = read(s, result.length)
  return result
end

-- Parses TLS records, and concatenates records of the same content type
local function parseTLSRecords(packets)
  assert(type(packets) == "string", "`packets` argument of string type expected")
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
  assert(type(record) == "table", "`record` argument of table type expected")
  assert(record.contentType == TLS_CONTENT_TYPES.Handshake, "handshake record expected")
  local data = {[0] = record.data}
  local result = {}
  while #data[0] > 0 do
    local handshakeType = uint8:unpack(read(data, 1))
    if not HANDSHAKE_TYPES[handshakeType] then
      error("unknown handshake message type: " .. handshakeType)
    end
    local len = uint24:unpack(read(data, 3))
    local hsData = read(data, len)
    result[#result+1] = hsDecoders[handshakeType](hsData)
  end
end

local function createTLSCompressed(tlsPlaintext, compression)
  local contentType, version, length, data = tlsPlaintext.contentType, tlsPlaintext.version, tlsPlaintext.length, tlsPlaintext.data
  if compression == "\x00" then -- No compression
    -- do nothing
  else
    error("unknown compression algorithm")
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
local function createCipherMac(cipher, mac, cipherKey, macKey, ivLen, cipherBlockLength)
  cipher, mac, cipherKey, macKey, ivLen, cipherBlockLength = copy(cipher), copy(mac), copy(cipherKey), copy(macKey), copy(ivLen), copy(cipherBlockLength)
  local iv = getRandom(ivLen)
  return setmetatable({}, {
    __index = {
      cipher = cipher,
      mac = mac,
      cipherKey = cipherKey,
      macKey = macKey,
      iv = iv,
      cipherBlockLength = cipherBlockLength
    },
    __newindex = function(self, k, v)
      error("the struct is read-only")
    end,
    __pairs = function(self)
      return pairs({
        cipher = cipher,
        mac = mac,
        cipherKey = cipherKey,
        macKey = macKey,
        iv = iv,
        cipherBlockLength = cipherBlockLength
      })
    end,
    __ipairs = function(self)
      return ipairs({
        cipher = cipher,
        mac = mac,
        cipherKey = cipherKey,
        macKey = macKey,
        iv = iv,
        cipherBlockLength = cipherBlockLength
      })
    end
  })
end

-- Only supports block ciphers
local function createTLSCiphertext(tlsCompressed, seqNum, cipherMac)
  local contentType, version, length, data = tlsCompressed.contentType, tlsCompressed.version, tlsCompressed.length, tlsCompressed.data
  seqNum.write = seqNum.write + 1
  local mac = cipherMac.mac(cipherMac.macKey, number2bytes(seqNum.write) .. uint8:pack(contentType) .. uint16:pack(version) .. data)
  local cipherData = data .. mac
  local padding = (#cipheredData + 1) % cipherMac.cipherBlockLength
  cipherData = cipherData .. uint8:pack(padding):rep(padding + 1)
  local encryptedData = cipherMac.cipher(cipherData, cipherMac.cipherKey, cipherMac.iv)
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

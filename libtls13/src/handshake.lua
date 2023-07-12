-- The TLS handshake protocol implementation.

local asn = require("tls13.asn")
local buffer = require("tls13.util.buffer")
local errors = require("tls13.error")
local hkdf = require("tls13.crypto.hkdf")
local record = require("tls13.record")
local util = require("tls13.util")
local utilMap = require("tls13.util.map")
local x509 = require("tls13.x509")

local lib = {}

local HELLO_RETRY_REQUEST_RANDOM = util.fromHex(
  "cf21ad74e59a6111be1d8c021e65b891\z
  c2a211167abb8c5e079e09e2c8a8339c"
)

local getCode = util.projectKey("code")

local function encodeCode(value)
  return (">I2"):pack(getCode(value))
end

lib.handshakeMessages = utilMap.makeBijectiveMap {
  clientHello = 1,
  serverHello = 2,
  newSessionTicket = 4,
  endOfEarlyData = 5,
  encryptedExtensions = 8,
  certificate = 11,
  certificateRequest = 13,
  certificateVerify = 15,
  finished = 20,
  keyUpdate = 24,
  messageHash = 254,
}

lib.tlsVersions = utilMap.makeBijectiveMap {
  tls13 = 0x0304,
}

lib.recognizedExtensions = {}

function lib.registerExtension(typeId, name, allowedMessages)
  assert(lib.recognizedExtensions[typeId] == nil, "extension type id conflict")
  assert(lib.recognizedExtensions[name] == nil, "extension name conflict")

  local entry = {
    type = typeId,
    name = name,
    allowedMessages = allowedMessages,
  }

  lib.recognizedExtensions[typeId] = entry
  lib.recognizedExtensions[name] = entry
end

lib.registerExtension(
  0, "serverName", {"clientHello", "encryptedExtensions"}
)

function lib.recognizedExtensions.serverName.decode(self)
  -- yes, really: the server sends an empty extension.
  return {}
end

function lib.recognizedExtensions.serverName.encode(self, _, extension)
  return self:encodeList(extension.serverNameList, 2, function(serverName)
    if serverName.hostname then
      assert(serverName.hostname ~= "")
      return (">B s2"):pack(0x00, serverName.hostname)
    end

    error("unknown name type in server name list entry")
  end)
end

lib.registerExtension(
  10, "supportedGroups", {"clientHello", "encryptedExtensions"}
)

function lib.recognizedExtensions.supportedGroups.decode(self)
  local namedGroupListSize, err = self:unpackMessage(">I2")

  if not namedGroupListSize then
    return nil, err
  end

  if namedGroupListSize == 0 then
    return self:sendAlert(errors.alert.decodeError.detail(
      "supported_groups extension contains empty list"
    ))
  end

  return self:withLimit(namedGroupListSize, function(self)
    local namedGroupList = {}

    while self:currentLimit().remaining > 0 do
      local code, err = self:unpackMessage(">I2")

      if not code then
        return nil, err
      end

      local namedGroup = self.__namedGroupCodes[code]

      if namedGroup then
        table.insert(namedGroupList, namedGroup)
      else
        table.insert(namedGroupList, {code = code})
      end
    end

    return {namedGroupList = namedGroupList}
  end)
end

function lib.recognizedExtensions.supportedGroups.encode(self, _, extension)
  assert(#extension.namedGroupList > 0)

  return self:encodeList(extension.namedGroupList, 2, encodeCode)
end

lib.registerExtension(
  13, "signatureAlgorithms", {"clientHello", "certificateRequest"}
)

local function decodeSignatureAlgorithms(self, signatureAlgorithmCodes)
  local supportedSignatureAlgorithmsSize, err = self:unpackMessage(">I2")

  if not supportedSignatureAlgorithmsSize then
    return nil, err
  end

  if supportedSignatureAlgorithmsSize == 0 then
    return self:sendAlert(errors.alert.decodeError.detail(
      "supported_signature_algorithms extension contains empty list"
    ))
  end

  return self:withLimit(supportedSignatureAlgorithmsSize, function(self)
    local supportedSignatureAlgorithms = {}

    while self:currentLimit().remaining > 0 do
      local signatureAlgorithm, err = self:decodeSignatureAlgorithm(
        signatureAlgorithmCodes, true
      )

      if signatureAlgorithm == nil then
        return nil, err
      elseif signatureAlgorithm then
        table.insert(supportedSignatureAlgorithms, signatureAlgorithm)
      else
        table.insert(supportedSignatureAlgorithms, {
          code = code,
          unknown = true,
        })
      end
    end

    return {supportedSignatureAlgorithms = supportedSignatureAlgorithms}
  end)
end

function lib.recognizedExtensions.signatureAlgorithms.decode(self)
  return decodeSignatureAlgorithms(self, self.__signatureAlgorithmCodes)
end

function lib.recognizedExtensions.signatureAlgorithms.encode(self, _, extension)
  local supportedSignatureAlgorithms = extension.supportedSignatureAlgorithms
  assert(#supportedSignatureAlgorithms > 0)

  return self:encodeList(supportedSignatureAlgorithms, 2, encodeCode)
end

lib.registerExtension(
  16, "applicationLayerProtocolNegotiation",
  {"clientHello", "encryptedExtensions"}
)

function lib.recognizedExtensions.applicationLayerProtocolNegotiation.decode(
    self)
  local protocolNameListSize, err = self:unpackMessage(">I2")

  if not protocolNameListSize then
    return nil, err
  end

  local protocolNameList = {}

  while self:currentLimit().remaining > 0 do
    local protocolNameSize, err = self:unpackMessage("B")

    if not protocolNameSize then
      return nil, err
    elseif protocolNameSize == 0 then
      return self:sendAlert(errors.alert.decodeError.detail(
        "ALPN protocol name list has empty entry"
      ))
    end

    local protocolName, err = self:consumeFromBuffer(protocolNameSize)

    if not protocolName then
      return nil, err
    end

    table.insert(protocolNameList, protocolName)
  end

  if #protocolNameList ~= 1 then
    return self:sendAlert(errors.alert.illegalParameter.detail(
      "server ALPN protocol name list must have exactly one entry"
    ))
  end

  return {protocolNameList = protocolNameList}
end

function lib.recognizedExtensions.applicationLayerProtocolNegotiation.encode(
    self, _, extension)
  assert(#extension.protocolNameList > 0)

  return self:encodeList(extension.protocolNameList, 2, function(protocolName)
    assert(#protocolName > 0)

    return (">s1"):pack(protocolName)
  end)
end

lib.registerExtension(
  43, "supportedVersions", {"clientHello", "serverHello", "helloRetryRequest"}
)

function lib.recognizedExtensions.supportedVersions.decode(self)
  local version, err = self:unpackMessage(">I2")

  if not version then
    return nil, err
  end

  return {selectedVersion = version}
end

function lib.recognizedExtensions.supportedVersions.encode(self, _, extension)
  assert(#extension.versions > 0)

  return self:encodeList(extension.versions, 1, function(version)
    return (">I2"):pack(version)
  end)
end

lib.registerExtension(
  44, "cookie", {"clientHello", "helloRetryRequest"}
)

function lib.recognizedExtensions.cookie.decode(self)
  local cookieSize, err = self:unpackMessage(">I2")

  if not cookieSize then
    return nil, err
  elseif cookieSize == 0 then
    return self:sendAlert(errors.alert.decodeError.detail(
      "cookie extension is empty"
    ))
  end

  local cookie, err = self:consumeFromBuffer(cookieSize)

  if not cookie then
    return nil, err
  end

  return {cookie = cookie}
end

function lib.recognizedExtensions.cookie.encode(self, _, extension)
  return (">s2"):pack(extension.cookie)
end

lib.registerExtension(
  50, "signatureAlgorithmsCert", {"clientHello", "certificateRequest"}
)

function lib.recognizedExtensions.signatureAlgorithmsCert.decode(self)
  return decodeSignatureAlgorithms(self, self.__certSignatureAlgorithmCodes)
end

function lib.recognizedExtensions.signatureAlgorithmsCert.encode(
    self, _, extension)
  local supportedSignatureAlgorithms = extension.supportedSignatureAlgorithms
  assert(#supportedSignatureAlgorithms > 0)

  return self:encodeList(supportedSignatureAlgorithms, 2, encodeCode)
end

lib.registerExtension(
  51, "keyShare", {"clientHello", "serverHello", "helloRetryRequest"}
)

function lib.recognizedExtensions.keyShare.decode(self, _, messageType)
  if messageType == "helloRetryRequest" then
    local code, err = self:unpackMessage(">I2")

    if not code then
      return nil, err
    end

    local namedGroup = self.__namedGroupCodes[code]

    if not namedGroup then
      return self:sendAlert(errors.alert.illegalParameter.detail(
        "group selected in key_share extension is unsupported"
      ))
    end

    return {selectedGroup = namedGroup}
  elseif messageType == "serverHello" then
    local code, err = self:unpackMessage(">I2")

    if not code then
      return nil, err
    end

    local namedGroup = self.__namedGroupCodes[code]

    if not namedGroup then
      return self:sendAlert(errors.alert.illegalParameter.detail(
        "server shared key exchange material in key_share extension \z
          for unsupported group"
      ))
    end

    local keyExchangeSize, err = self:unpackMessage(">I2")

    if not keyExchangeSize then
      return nil, err
    elseif keyExchangeSize == 0 then
      return self:sendAlert(errors.alert.decodeError.detail(
        "server key exchange material in key_share extension is empty"
      ))
    end

    local keyExchange, err = self:consumeFromBuffer(keyExchangeSize)

    if not keyExchange then
      return nil, err
    end

    local keys, err = namedGroup:decodePublicKey(keyExchange)

    if not keys then
      return self:sendAlert(
        errors.alert.illegalParameter.serverKey:wrapping(err, err)
      )
    end

    return {
      serverShare = {
        group = namedGroup,
        keyExchange = keyExchange,
        keys = keys,
      },
    }
  else
    error("unsupported message: " .. messageType)
  end
end

function lib.recognizedExtensions.keyShare.encode(self, _, extension)
  return self:encodeList(extension.clientShares, 2, function(entry)
    local keyExchange = entry.group:encodePublicKey(entry.keys)
    return (">I2 s2"):pack(entry.group.code, keyExchange)
  end)
end

local meta = {
  __index = {
    __messageEncoders = {
      [lib.handshakeMessages.clientHello] = function(self, message)
        local cipherSuites = {}

        for i, suite in ipairs(message.cipherSuites) do
          cipherSuites[i] = (">I2"):pack(suite)
        end

        local extensions = self:encodeExtensions(message.extensions)

        return (">I2 c32 s1 s2 s1 s2"):pack(
          record.TLS_LEGACY_VERSION,
          message.random,
          message.legacySessionId,
          table.concat(cipherSuites),
          "\0", -- 'null' compression method
          extensions
        )
      end,

      [lib.handshakeMessages.certificate] = function(self, message)
        local certificates = {}

        for _, entry in ipairs(message.certificateList) do
          table.insert(certificates, (">s3 s2"):pack(
            entry.certData,
            self:encodeExtensions(entry.extensions)
          ))
        end

        return (">s1 s3"):pack(
          message.certificateRequestContext,
          table.concat(certificates)
        )
      end,

      [lib.handshakeMessages.certificateVerify] = function(self, message)
        return (">I2 s2"):pack(message.algorithm.code, message.signature)
      end,

      [lib.handshakeMessages.finished] = function(self, message)
        return message.verifyData
      end,

      [lib.handshakeMessages.endOfEarlyData] = function(self, message)
        return ""
      end,

      [lib.handshakeMessages.keyUpdate] = function(self, message)
        return message.requestUpdate and "\1" or "\0"
      end,

      [lib.handshakeMessages.messageHash] = function(self, message)
        return message.hash
      end,
    },

    __messageDecoders = {
      [lib.handshakeMessages.serverHello] = function(self)
        local legacyVersion, random, sessionIdLength =
          self:unpackMessage(">I2 c32 B")

        if not legacyVersion then
          return nil, random
        end

        if sessionIdLength ~= 0 and sessionIdLength ~= 32 then
          return self:sendAlert(errors.alert.decodeError.sessionId(
            sessionIdLength
          ))
        end

        local legacySessionIdEcho, err = self:consumeFromBuffer(sessionIdLength)

        if not legacySessionIdEcho then
          return nil, err
        end

        local cipherSuite, legacyCompressionMethod = self:unpackMessage(">I2B")

        if legacyCompressionMethod ~= 0 then
          return self:sendAlert(errors.alert.decodeError.compressionMethod(
            legacyCompressionMethod
          ))
        end

        local messageType = "serverHello"

        if random == HELLO_RETRY_REQUEST_RANDOM then
          messageType = "helloRetryRequest"
        end

        local extensions, err = self:decodeExtensions(messageType)

        if not extensions then
          return nil, err
        end

        return {
          type = "serverHello",

          legacyVersion = legacyVersion,
          random = random,
          legacySessionIdEcho = legacySessionIdEcho,
          cipherSuite = cipherSuite,
          legacyCompressionMethod = legacyCompressionMethod,
          extensions = extensions,
        }
      end,

      [lib.handshakeMessages.newSessionTicket] = function(self)
        local ticketLifetime, ticketAgeAdd = self:unpackMessage(">I4 I4")

        if not ticketLifetime then
          return nil, ticketAgeAdd
        end

        local ticketNonceSize, err = self:unpackMessage("B")

        if not ticketNonceSize then
          return nil, err
        end

        local ticketNonce, err = self:consumeFromBuffer(ticketNonceSize)

        if not ticketNonce then
          return nil, err
        end

        local ticketSize, err = self:unpackMessage(">I2")

        if not ticketSize then
          return nil, err
        elseif ticketSize == 0 then
          return self:sendAlert(errors.alert.decodeError.detail(
            "session ticket is empty"
          ))
        end

        local ticket, err = self:consumeFromBuffer(ticketSize)

        if not ticket then
          return nil, err
        end

        local extensions, err = self:decodeExtensions("newSessionTicket", true)

        if not extensions then
          return nil, err
        end

        return {
          type = "newSessionTicket",

          ticketLifetime = ticketLifetime,
          ticketAgeAdd = ticketAgeAdd,
          ticketNonce = ticketNonce,
          ticket = ticket,
          extensions = extensions,
        }
      end,

      [lib.handshakeMessages.encryptedExtensions] = function(self)
        local extensions, err = self:decodeExtensions("encryptedExtensions")

        if not extensions then
          return nil, err
        end

        return {
          type = "encryptedExtensions",

          extensions = extensions,
        }
      end,

      [lib.handshakeMessages.certificate] = function(self)
        local certificateRequestContextSize, err = self:unpackMessage("B")

        if not certificateRequestContextSize then
          return nil, err
        end

        local certificateRequestContext, err =
          self:consumeFromBuffer(certificateRequestContextSize)

        if not certificateRequestContext then
          return nil, err
        end

        local certificateListSize, err = self:unpackMessage(">I3")

        if not certificateListSize then
          return nil, err
        end

        return self:withLimit(certificateListSize, function(self)
          local entries = {}

          while self:currentLimit().remaining > 0 do
            local certDataSize, err = self:unpackMessage(">I3")

            if not certDataSize then
              return nil, err
            elseif certDataSize == 0 then
              return self:sendAlert(errors.alert.decodeError.detail(
                "certificate data is empty"
              ))
            end

            local certData, err = self:consumeFromBuffer(certDataSize)

            if not certData then
              return nil, err
            end

            local extensions, err = self:decodeExtensions("certificate")

            if not extensions then
              return nil, err
            end

            local certAsn, err = asn.decode(certData)

            if not certAsn then
              return self:sendAlert(
                errors.alert.badCertificate.asn:wrapping(err, err)
              )
            end

            local cert, err = x509.parseCertificateFromAsn(certAsn)

            if not cert then
              return self:sendAlert(
                errors.alert.badCertificate.parse:wrapping(err, err)
              )
            end

            table.insert(entries, {
              cert = cert,
              extensions = extensions,
            })
          end

          return {
            type = "certificate",

            certificateRequestContext = certificateRequestContext,
            certificateList = entries,
          }
        end)
      end,

      [lib.handshakeMessages.certificateRequest] = function(self)
        local certificateRequestContextSize, err = self:unpackMessage("B")

        if not certificateRequestContextSize then
          return nil, err
        end

        local certificateRequestContext, err =
          self:consumeFromBuffer(certificateRequestContextSize)

        if not certificateRequestContext then
          return nil, err
        end

        local extensions, err = self:decodeExtensions("certificateRequest")

        if not extensions then
          return nil, err
        end

        return {
          type = "certificateRequest",

          certificateRequestContext = certificateRequestContext,
          extensions = extensions,
        }
      end,

      [lib.handshakeMessages.certificateVerify] = function(self)
        local algorithm, err = self:decodeSignatureAlgorithm(
          self.__signatureAlgorithmCodes
        )

        if not algorithm then
          return nil, err
        end

        local signatureSize, err = self:unpackMessage(">I2")

        if not signatureSize then
          return nil, err
        end

        local signature, err = self:consumeFromBuffer(signatureSize)

        if not signature then
          return nil, err
        end

        return {
          type = "certificateVerify",

          algorithm = algorithm,
          signature = signature,
        }
      end,

      [lib.handshakeMessages.finished] = function(self)
        local hashSize = self.__hmac.HASH_SIZE
        local verifyData = self:consumeFromBuffer(hashSize)

        return {
          type = "finished",

          verifyData = verifyData,
        }
      end,

      [lib.handshakeMessages.keyUpdate] = function(self)
        local updateRequested = self:unpackMessage("B")

        if updateRequested == 0 then
          updateRequested = false
        elseif updateRequested == 1 then
          updateRequested = true
        else
          return self:sendAlert(
            errors.alert.illegalParameter.keyUpdate(updateRequested)
          )
        end

        return {
          type = "keyUpdate",
          updateRequested = updateRequested,
        }
      end,
    },

    readRecord = function(self, ...)
      local allowedTypes = {...}
      local rec, err = self.__record:read()

      if not rec then
        return nil, err
      end

      if not util.contains(allowedTypes, rec.type) then
        local expectedNames = {}

        for _, messageType in ipairs(allowedTypes) do
          table.insert(expectedNames, record.contentTypes[messageType])
        end

        return self.__record:sendAlert(
          errors.alert.unexpectedMessage.unknownContentType(
            table.concat(expectedNames, ", "),
            record.contentTypes[rec.type]
          )
        )
      end

      if rec.type ~= record.contentTypes.handshake then
        return rec
      end

      if #rec.content == 0 then
        return self:sendAlert(errors.alert.decodeError.detail(
          "received empty handshake message"
        ))
      end

      self.__buf:append(rec.content)

      return rec
    end,

    bufferHandshakeMessage = function(self, count)
      while self.__buf:remaining() < count do
        local result, err = self:readRecord(record.contentTypes.handshake)

        if not result then
          return nil, err
        end
      end

      return true
    end,

    pushLimit = function(self, limit)
      table.insert(self.__limits, {
        count = limit,
        remaining = limit,
      })
    end,

    popLimit = function(self)
      assert(#self.__limits > 0)

      local limit = table.remove(self.__limits)

      if limit.remaining ~= 0 then
        return self:sendAlert(errors.alert.decodeError.trailingJunk())
      end

      local currentLimit = self:currentLimit()

      if currentLimit then
        currentLimit.remaining = currentLimit.remaining - limit.count

        if currentLimit.remaining < 0 then
          return self:sendAlert(
            errors.alert.decodeError.lengthOutOfRange(limit.count)
          )
        end
      end

      return true
    end,

    currentLimit = function(self)
      return self.__limits[#self.__limits]
    end,

    withLimit = function(self, n, f, ...)
      self:pushLimit(n)
      local result, err = f(self, ...)

      if not result then
        return nil, err
      end

      local success, err = self:popLimit()

      if not success then
        return nil, err
      end

      return result
    end,

    consumeFromBuffer = function(self, n)
      if self.__buf:remaining() < n then
        return self:sendAlert(errors.alert.decodeError.lengthOutOfRange(
          n - self.__buf:remaining()
        ))
      end

      local currentLimit = self:currentLimit()

      if currentLimit then
        currentLimit.remaining = currentLimit.remaining - n

        if currentLimit.remaining < 0 then
          return self:sendAlert(
            errors.alert.decodeError.limitExceeded(currentLimit.count)
          )
        end
      end

      return self.__buf:consume(n)
    end,

    unpackMessage = function(self, fmt)
      local data, err = self:consumeFromBuffer(string.packsize(fmt))

      if not data then
        return nil, err
      end

      local result = table.pack(fmt:unpack(data))

      return table.unpack(result, 1, result.n - 1)
    end,

    decodeHandshakeMessage = function(self)
      if not self:hasUnreadData() then
        local rec, err = self:readRecord(
          record.contentTypes.handshake,
          record.contentTypes.alert
        )

        if not rec then
          return nil, err
        elseif rec.type == record.contentTypes.alert then
          return self:_alert(rec)
        end
      end

      local fmt = ">BI3"
      local success, err = self:bufferHandshakeMessage(string.packsize(fmt))

      if not success then
        return nil, err
      end

      local messageHeader = self.__buf:peek(string.packsize(fmt))
      local messageType, length = self:unpackMessage(fmt)

      if not messageType then
        return nil, length
      end

      success, err = self:bufferHandshakeMessage(length)

      if not success then
        return nil, err
      end

      local messageBody = self.__buf:peek(length)

      return self:withLimit(length, function(self)
        if self.__messageDecoders[messageType] then
          local result, err = self.__messageDecoders[messageType](self)

          if not result then
            return nil, err
          end

          result.messageHeader = messageHeader
          result.messageBody = messageBody

          return result
        end

        return self:sendAlert(
          errors.alert.unexpectedMessage.unknownHandshakeMessage(messageType)
        )
      end)
    end,

    decodeExtensions = function(self, messageType, allowUnknownExtensions)
      local length, err = self:unpackMessage(">I2")

      if not length then
        return nil, err
      end

      return self:withLimit(length, function(self)
        local extensions = {}

        while self:currentLimit().remaining > 0 do
          local extension, err =
            self:decodeExtension(messageType, allowUnknownExtensions)

          if extension == false then
            goto continue
          elseif not extension then
            return nil, err
          end

          if extensions[extension.type] then
            return self:sendAlert(errors.alert.decodeError.duplicateExtension(
              extension.name or extension.type
            ))
          end

          table.insert(extensions, extension)
          extensions[extension.type] = extension

          ::continue::
        end

        return extensions
      end)
    end,

    decodeExtension = function(self, messageType, allowUnknown)
      local extensionType, extensionLength = self:unpackMessage(">I2I2")

      if not extensionType then
        return nil, extensionLength
      end

      return self:withLimit(extensionLength, function(self)
        local entry = lib.recognizedExtensions[extensionType]

        if not entry and allowUnknown then
          self:consumeFromBuffer(extensionLength)

          return false
        end

        if not entry then
          return self:sendAlert(
            errors.alert.unsupportedExtension.unrecognized(extensionType)
          )
        elseif not util.contains(entry.allowedMessages, messageType) then
          return self:sendAlert(
            errors.alert.unsupportedExtension.prohibitedMessage(
              entry.name,
              messageType
            )
          )
        elseif not entry.decode then
          return self:sendAlert(
            errors.alert.unsupportedExtension.cannotDecode(entry.name)
          )
        elseif not self.__allowedExtensions[entry.name] then
          return self:sendAlert(
            errors.alert.unsupportedExtension.notOffered(entry.name)
          )
        end

        local result, err = entry.decode(self, entry, messageType)

        if not result then
          return nil, err
        end

        result.type = extensionType
        result.name = entry.name

        return result
      end)
    end,

    encodeExtensions = function(self, extensions)
      local result = {}

      for i, extension in ipairs(extensions) do
        result[i] = self:encodeExtension(extension)
      end

      return table.concat(result)
    end,

    encodeExtension = function(self, extension)
      local recognizedExtension =
        lib.recognizedExtensions[extension.type]
        or lib.recognizedExtensions[extension.name]
      assert(recognizedExtension, "unrecognized extension")

      local content = recognizedExtension
        .encode(self, recognizedExtension, extension)

      extension.type = extension.type or recognizedExtension.type
      extension.name = extension.name or recognizedExtension.name

      return (">I2 s2"):pack(extension.type, content)
    end,

    decodeSignatureAlgorithm = function(
        self, signatureAlgorithmCodes, allowUnknown)
      local code, err = self:unpackMessage(">I2")

      if not code then
        return nil, err
      end

      local signatureAlgorithm = signatureAlgorithmCodes[code]

      if not signatureAlgorithm then
        if allowUnknown then
          return false
        else
          return self:sendAlert(
            errors.alert.illegalParameter.signatureAlgorithm(code)
          )
        end
      end

      return signatureAlgorithm
    end,

    hasUnreadData = function(self)
      return self.__buf:remaining() > 0
    end,

    encode = function(self, message)
      local messageType = assert(lib.handshakeMessages[message.type])
      local encoder = self.__messageEncoders[messageType]

      return (">B s3"):pack(messageType, encoder(self, message))
    end,

    encodeList = function(self, tbl, lengthSize, entryEncoder)
      local entries = {}

      for _, entry in ipairs(tbl) do
        table.insert(entries, (entryEncoder(entry)))
      end

      return (">s" .. lengthSize):pack(table.concat(entries))
    end,

    writeMessage = function(self, message, updateTranscriptHash)
      if type(message) ~= "string" then
        local encoded = self:encode(message)
        message.encoded = encoded
        message = encoded
      end

      if updateTranscriptHash then
        self.__transcriptHash:update(message)
      end

      return self.__record:write(record.contentTypes.handshake, message)
    end,

    sendAlert = function(self, err)
      return self.__record:sendAlert(err)
    end,

    close = function(self)
      if self.__status == "initial" then
        self.__record:close()

        return true
      elseif self.__status == "handshake"
          or self.__status == "handshake-canceled" then
        self.__status = "handshake-canceled"

        return false
      elseif self.__status == "established" then
        local result, err = true

        if not self.__record:fatalAlertSent() then
          result, err = self.__record:sendAlert(errors.alert.closeNotify())
        end

        self.__record:close()

        return result, err
      end
    end,

    awaitCommand = function(self, response)
      return coroutine.yield("standby", response)
    end,

    expect = function(self, ...)
      local types = {...}
      local message, err = self:decodeHandshakeMessage()

      if not message then
        return nil, err
      end

      if not util.contains(types, message.type) then
        return self:sendAlert(errors.alert.unexpectedMessage())
      end

      return message
    end,

    updateTranscriptHash = function(self, message)
      if message.encoded then
        self.__transcriptHash:update(message.encoded)
      else
        self.__transcriptHash:update(message.messageHeader)
        self.__transcriptHash:update(message.messageBody)
      end
    end,

    generateKeyShares = function(self)
      local keys = {}

      for _, namedGroup in ipairs(self.__namedGroups) do
        if namedGroup.generateEagerly then
          table.insert(keys, {group = namedGroup})
        end
      end

      for _, key in ipairs(keys) do
        key.keys = key.group:generateKeyPair()
      end

      return keys
    end,

    updateAllowedExtensions = function(self, extensions)
      for _, extension in ipairs(extensions) do
        self.__allowedExtensions[extension.name] = true
      end
    end,

    checkServerHello = function(self, serverHello, clientHello)
      -- the RFC has conflicting requirements as to when the version should be
      -- checked, so let's do it the first thing here...
      local supportedVersions =
        serverHello.extensions[lib.recognizedExtensions.supportedVersions.type]

      if not supportedVersions then
        -- is that ok? not sure...
        return self:sendAlert(errors.alert.protocolVersion.noExtension())
      elseif supportedVersions.selectedVersion ~= lib.tlsVersions.tls13 then
        return self:sendAlert(errors.alert.illegalParameter.selectedVersion(
          supportedVersions.selectedVersion >> 8,
          supportedVersions.selectedVersion & 0xff
        ))
      end

      if serverHello.legacySessionIdEcho ~= clientHello.legacySessionId then
        return self:sendAlert(errors.alert.illegalParameter.detail(
          "legacy_session_id_echo in ServerHello does not match \z
            legacy_session_id in ClientHello"
        ))
      end

      local _, cipherSuite =
        util.find(self.__cipherSuites, function(cipherSuite)
          return cipherSuite.code == serverHello.cipherSuite
        end)

      if not cipherSuite then
        return self:sendAlert(errors.alert.illegalParameter.cipherSuiteUnknown(
          serverHello.cipherSuite
        ))
      elseif not util.contains(
            clientHello.cipherSuites, serverHello.cipherSuite
          ) then
        return self:sendAlert(
          errors.alert.illegalParameter.cipherSuite(cipherSuite.name)
        )
      end

      assert(serverHello.legacyCompressionMethod == 0x00)

      return cipherSuite
    end,

    getKeyShare = function(self, clientKeyShare, serverKeyShare, mustMakeKeys)
      if not serverKeyShare then
        return self:sendAlert(
          errors.alert.missingExtension.extension("key_share")
        )
      end

      local serverNamedGroup, serverKeys

      if serverKeyShare.serverShare then
        serverNamedGroup = serverKeyShare.serverShare.group
        serverKeys = serverKeyShare.serverShare.keys
      else
        serverNamedGroup = serverKeyShare.selectedGroup
      end

      for _, namedGroupEntry in ipairs(clientKeyShare.clientShares) do
        if namedGroupEntry.group.code == serverNamedGroup.code then
          if mustMakeKeys then
            return self:sendAlert(
              errors.alert.illegalParameter.groupAlreadyHasShare(
                namedGroupEntry.name
              )
            )
          end

          return namedGroupEntry.group, namedGroupEntry.keys, serverKeys
        end
      end

      if not mustMakeKeys then
        return self:sendAlert(
          errors.alert.illegalParameter.groupNoShare(serverNamedGroup.name)
        )
      end

      local clientKeys = serverNamedGroup:generateKeyPair()

      return serverNamedGroup, clientKeys, serverKeys
    end,

    useCipherSuite = function(self, cipherSuite)
      self.__transcriptHash = cipherSuite.hash()
      self.__hmac = cipherSuite.hmac
      self.__hkdf = hkdf.hkdf(self.__hmac)
      self.__aead = cipherSuite.aead

      -- needed for deriveSecret
      self.__emptyStringHash = cipherSuite.hash():finish()
    end,

    hkdfExpandLabel = function(self, secret, label, context, length)
      local hkdfLabel = (">I2 s1 s1"):pack(
        length,
        "tls13 " .. label,
        context
      )

      return self.__hkdf:expand(hkdfLabel, length, secret)
    end,

    getTranscriptHash = function(self)
      return self.__transcriptHash:copy():finish()
    end,

    deriveSecret = function(self, secret, label, hash)
      return self:hkdfExpandLabel(secret, label, hash, #hash)
    end,

    deriveEarlySecret = function(self)
      -- PSK is not provided (nor supported)
      local zeros = ("\0"):rep(self.__hmac.HASH_SIZE)
      local earlySecret = self.__hkdf:extract(zeros, zeros)

      return {
        earlySecret = earlySecret,
      }
    end,

    generateKeys = function(self, secret)
      return {
        writeKey =
          self:hkdfExpandLabel(secret, "key", "", self.__aead.KEY_SIZE),
        writeIv = self:hkdfExpandLabel(secret, "iv", "", self.__aead.IV_SIZE),
      }
    end,

    deriveHandshakeSecrets = function(self, earlySecret, ikm)
      local handshakeSecret = self.__hkdf:extract(
        ikm,
        self:deriveSecret(earlySecret, "derived", self.__emptyStringHash)
      )
      local transcriptHash = self:getTranscriptHash()
      local clientTrafficSecret =
        self:deriveSecret(handshakeSecret, "c hs traffic", transcriptHash)
      local serverTrafficSecret =
        self:deriveSecret(handshakeSecret, "s hs traffic", transcriptHash)

      return {
        handshakeSecret = handshakeSecret,

        clientTrafficSecret = clientTrafficSecret,
        serverTrafficSecret = serverTrafficSecret,

        client = self:generateKeys(clientTrafficSecret),
        server = self:generateKeys(serverTrafficSecret),
      }
    end,

    deriveApplicationSecrets = function(self, handshakeSecret)
      local masterSecret = self.__hkdf:extract(
        ("\0"):rep(self.__hmac.HASH_SIZE),
        self:deriveSecret(
          handshakeSecret.handshakeSecret,
          "derived",
          self.__emptyStringHash
        )
      )
      local transcriptHash = self:getTranscriptHash()
      local clientTrafficSecret =
        self:deriveSecret(masterSecret, "c ap traffic", transcriptHash)
      local serverTrafficSecret =
        self:deriveSecret(masterSecret, "s ap traffic", transcriptHash)

      return {
        clientTrafficSecret = clientTrafficSecret,
        serverTrafficSecret = serverTrafficSecret,

        client = self:generateKeys(clientTrafficSecret),
        server = self:generateKeys(serverTrafficSecret),
      }
    end,

    updateApplicationSecret = function(self, side, applicationSecret)
      if side == "rx" then
        side = "server"
      else
        side = "client"
      end

      local trafficSecret = self:hkdfExpandLabel(
        applicationSecret[side .. "TrafficSecret"],
        "traffic upd",
        "",
        self.__hmac.HASH_SIZE
      )
      local keys = self:generateKeys(trafficSecret)

      local result = {
        clientTrafficSecret = applicationSecret.clientTrafficSecret,
        serverTrafficSecret = applicationSecret.serverTrafficSecret,

        client = applicationSecret.client,
        server = applicationSecret.server,
      }

      result[side .. "TrafficSecret"] = trafficSecret
      result[side] = keys

      return result
    end,

    useTrafficKeys = function(self, side, keys)
      local aead = self.__aead(keys.writeKey)
      self.__record:changeKeys(side, aead, keys.writeIv)
    end,

    logApplicationSecret = function(self, side, applicationSecret)
      applicationSecret = applicationSecret or self.__applicationSecret

      if side == "tx" then
        self.__keyLogFile:write(
          ("CLIENT_TRAFFIC_SECRET_%d %s %s\n"):format(
            self.__keyUpdateCount.tx,
            util.toHex(self.__clientRandom),
            util.toHex(applicationSecret.clientTrafficSecret)
          )
        )
      elseif side == "rx" then
        self.__keyLogFile:write(
          ("SERVER_TRAFFIC_SECRET_%d %s %s\n"):format(
            self.__keyUpdateCount.rx,
            util.toHex(self.__clientRandom),
            util.toHex(applicationSecret.serverTrafficSecret)
          )
        )
      end
    end,

    --[[ Handshake state machine ]]--

    handshake = function(self)
      return self:_hsClientHello()
    end,

    callUnlessCanceled = function(self, f, ...)
      if self.__status == "handshake-canceled"
          and not self.__record:fatalAlertSent() then
        local result, alert = self:sendAlert(errors.alert.userCanceled())

        if not result and alert ~= errors.tls.localCloseAlert then
          return nil, alert
        end

        local result, err = self:sendAlert(errors.alert.closeNotify())

        if not result and err ~= errors.tls.localCloseAlert then
          return nil, err
        end

        self.__record:close()

        return nil, alert
      end

      return f(self, ...)
    end,

    _alert = function(self, rec)
      if rec.alert == errors.tls.remoteAlert then
        self.__record:close()

        return nil, rec.alert
      end

      return nil, rec.alert
    end,

    _hsClientHello = function(self)
      local random = self.__rng(32)

      if self.__keyLogFile then
        self.__clientRandom = random
      end

      local cipherSuites = {}

      for _, cipherSuite in ipairs(self.__cipherSuites) do
        table.insert(cipherSuites, cipherSuite.code)
      end

      local extensions = {}

      -- supported_versions: TLS 1.3 only
      table.insert(extensions, {
        name = "supportedVersions",
        versions = {lib.tlsVersions.tls13},
      })

      -- signature_algorithms
      table.insert(extensions, {
        name = "signatureAlgorithms",
        supportedSignatureAlgorithms = self.__signatureAlgorithms,
      })

      -- signature_algorithms_cert
      table.insert(extensions, {
        name = "signatureAlgorithmsCert",
        supportedSignatureAlgorithms = self.__certSignatureAlgorithms,
      })

      -- supported_groups
      table.insert(extensions, {
        name = "supportedGroups",
        namedGroupList = self.__namedGroups,
      })

      -- key_share
      local keys = self:generateKeyShares()
      table.insert(extensions, {
        name = "keyShare",
        clientShares = keys,
      })

      -- server_name
      if self.__serverNames then
        table.insert(extensions, {
          name = "serverName",
          serverNameList = self.__serverNames,
        })
      end

      -- application_layer_protocol_negotiation
      if self.__alpnProtocols then
        table.insert(extensions, {
          name = "applicationLayerProtocolNegotiation",
          protocolNameList = self.__alpnProtocols,
        })
      end

      self:updateAllowedExtensions(extensions)
      -- allowed regardless of whether we send it or not (we don't)
      self.__allowedExtensions.cookie = true

      local clientHello = {
        type = "clientHello",

        legacyVersion = record.TLS_LEGACY_VERSION,
        random = random,
        legacySessionId = "",
        cipherSuites = cipherSuites,
        extensions = extensions,
      }

      local result, err = self:writeMessage(clientHello)

      if not result then
        return nil, err
      end

      self.__status = "handshake"
      self.__record:setChangeCipherSpecAllowed(true)

      local serverHello, err = self:expect("serverHello")

      if not serverHello then
        return nil, err
      end

      return self:_hsServerHelloOrRetryReq(serverHello, clientHello)
    end,

    _hsServerHelloOrRetryReq =
      function(self, serverHello, clientHello, allowRetry)
        if serverHello.random == HELLO_RETRY_REQUEST_RANDOM then
          return self:_hsHelloRetryRequest(serverHello, clientHello)
        else
          return self:_hsServerHello(serverHello, clientHello)
        end
      end,

    _hsServerHello = function(self, serverHello, clientHello)
      self.__establishedContext.stage = "serverHello"

      local cipherSuite, err = self:checkServerHello(serverHello, clientHello)

      if not cipherSuite then
        return nil, err
      end

      self:useCipherSuite(cipherSuite)
      self:updateTranscriptHash(clientHello)
      self:updateTranscriptHash(serverHello)

      self.__establishedContext.cipherSuite = cipherSuite

      -- if the handshake is canceled at this point, we have to update the keys
      -- anyway so we can send an alert
      return self:_hsEngageHandshakeProtection(clientHello, serverHello)
    end,

    _hsHelloRetryRequest = function(self, helloRetryRequest, clientHello)
      self.__establishedContext.stage = "helloRetryRequest"
      self.__establishedContext.helloRetried = true

      local cipherSuite, err =
        self:checkServerHello(helloRetryRequest, clientHello)

      if not cipherSuite then
        return nil, err
      end

      self:useCipherSuite(cipherSuite)
      self:updateTranscriptHash(clientHello)
      local messageHash = {
        type = "messageHash",
        hash = self.__transcriptHash:finish(),
      }
      self:useCipherSuite(cipherSuite)
      self.__transcriptHash:update(self:encode(messageHash))
      self:updateTranscriptHash(helloRetryRequest)

      self.__establishedContext.cipherSuite = cipherSuite

      local extensions = {}
      local clientKeyShareIdx, clientKeyShare

      for i, extension in ipairs(clientHello.extensions) do
        if extension.name == "keyShare" then
          clientKeyShareIdx = i
          clientKeyShare = extension
        end

        table.insert(extensions, extension)
      end

      assert(clientKeyShare)

      local namedGroup, clientKeys = self:getKeyShare(
        clientKeyShare,
        helloRetryRequest.extensions[lib.recognizedExtensions.keyShare.type],
        true
      )

      if not namedGroup then
        return nil, clientKeys
      end

      extensions[clientKeyShareIdx] = {
        name = "keyShare",
        clientShares = {{
          group = namedGroup,
          keys = clientKeys,
        }},
      }

      local cookie =
        helloRetryRequest.extensions[lib.recognizedExtensions.cookie.type]

      if cookie then
        table.insert(extensions, cookie)
      end

      self.__allowedExtensions = {}
      self:updateAllowedExtensions(extensions)

      local clientHello2 = {
        type = "clientHello",
        legacyVersion = clientHello.legacyVersion,
        random = clientHello.random,
        legacySessionId = clientHello.legacySessionId,
        cipherSuites = clientHello.cipherSuites,
        extensions = extensions,
      }
      local result, err = self:writeMessage(clientHello2, true)

      if not result then
        return nil, err
      end

      local serverHello, err = self:expect("serverHello")

      if not serverHello then
        return nil, err
      end

      return self:_hsServerHello2(
        serverHello,
        clientHello,
        helloRetryRequest,
        clientHello2
      )
    end,

    _hsServerHello2 =
      function(self, serverHello, clientHello, helloRetryRequest, clientHello2)
        self.__establishedContext.stage = "serverHello2"

        local cipherSuite, err =
          self:checkServerHello(serverHello, clientHello2)

        if not cipherSuite then
          return nil, err
        end

        if serverHello.cipherSuite ~= helloRetryRequest.cipherSuite then
          return self:sendAlert(
            errors.alert.illegalParameter.cipherSuiteChanged(
              cipherSuite.name,
              self.__establishedContext.cipherSuite.code
            )
          )
        end

        local serverKeyShareOld =
          helloRetryRequest.extensions[lib.recognizedExtensions.keyShare.type]
        local serverKeyShareNew =
          serverHello.extensions[lib.recognizedExtensions.keyShare.type]

        if serverKeyShareOld and serverKeyShareNew
            and serverKeyShareOld.selectedGroup.code
              ~= serverKeyShareNew.serverShare.group.code then
          return self:sendAlert(errors.alert.illegalParameter.namedGroupChanged(
            serverKeyShareNew.serverShare.group.name,
            serverKeyShareOld.selectedGroup.name
          ))
        end

        self:updateTranscriptHash(serverHello)

        return self:_hsEngageHandshakeProtection(clientHello2, serverHello)
      end,

    _hsEngageHandshakeProtection = function(self, clientHello, serverHello)
      local _, clientKeyShare =
        util.find(clientHello.extensions, function(extension)
          return extension.name == "keyShare"
        end)
      local serverKeyShare =
        serverHello.extensions[lib.recognizedExtensions.keyShare.type]
      local namedGroup, clientShare, serverShare =
        self:getKeyShare(clientKeyShare, serverKeyShare, false)

      if not namedGroup then
        return nil, clientShare
      end

      if self:hasUnreadData() then
        -- a record spans the key change
        return self:sendAlert(
          errors.alert.unexpectedMessage.recordSpansKeyChange()
        )
      end

      self.__establishedContext.namedGroup = namedGroup

      local sharedSecret, err =
        namedGroup:deriveSharedSecret(clientShare, serverShare)

      if not sharedSecret then
        return self:sendAlert(
          errors.alert.illegalParameter.invalidGroupElement:wrapping(err)
        )
      end

      local earlySecret = self:deriveEarlySecret().earlySecret
      local handshakeSecrets =
        self:deriveHandshakeSecrets(earlySecret, sharedSecret)

      self:useTrafficKeys("rx", handshakeSecrets.server)
      self:useTrafficKeys("tx", handshakeSecrets.client)
      handshakeSecrets.client = nil
      handshakeSecrets.server = nil

      if self.__keyLogFile then
        self.__keyLogFile:write(
          ("CLIENT_HANDSHAKE_TRAFFIC_SECRET %s %s\n"):format(
            util.toHex(self.__clientRandom),
            util.toHex(handshakeSecrets.clientTrafficSecret)
          )
        )
        self.__keyLogFile:write(
          ("SERVER_HANDSHAKE_TRAFFIC_SECRET %s %s\n"):format(
            util.toHex(self.__clientRandom),
            util.toHex(handshakeSecrets.serverTrafficSecret)
          )
        )
      end

      local encryptedExtensions, err = self:expect("encryptedExtensions")

      if not encryptedExtensions then
        return nil, err
      end

      return self:callUnlessCanceled(
        self._hsEncryptedExtensions,
        encryptedExtensions,
        handshakeSecrets
      )
    end,

    _hsEncryptedExtensions =
      function(self, encryptedExtensions, handshakeSecret)
        self.__establishedContext.stage = "encryptedExtensions"
        self:updateTranscriptHash(encryptedExtensions)

        local alpn = encryptedExtensions.extensions[
          lib.recognizedExtensions.applicationLayerProtocolNegotiation.type
        ]

        if alpn then
          self.__establishedContext.alpnProtocol = alpn.protocolNameList[1]
        end

        local message, err = self:expect(
          "certificateRequest",
          "certificate"
        )

        if not message then
          return nil, err
        end

        if message.type == "certificateRequest" then
          return self:callUnlessCanceled(
            self._hsCertificateRequest,
            message,
            handshakeSecret
          )
        else
          return self:callUnlessCanceled(
            self._hsServerCertificate,
            message,
            handshakeSecret
          )
        end
      end,

    _hsCertificateRequest = function(self, certificateRequest, handshakeSecret)
      self.__establishedContext.stage = "certificateRequest"
      self.__establishedContext.clientCertificateRequested = true
      self:updateTranscriptHash(certificateRequest)

      if certificateRequest.certificateRequestContext ~= "" then
        return self:sendAlert(errors.alert.illegalParameter())
      end

      local signatureAlgorithms = certificateRequest.extensions[
        lib.recognizedExtensions.signatureAlgorithms.type
      ]

      if not signatureAlgorithms then
        return self:sendAlert(errors.alert.missingExtension.extension(
          "signature_algorithms"
        ))
      end

      local certificate, err = self:expect("certificate")

      if not certificate then
        return nil, err
      end

      return self:callUnlessCanceled(
        self._hsServerCertificate,
        certificate,
        handshakeSecret,
        certificateRequest
      )
    end,

    _hsServerCertificate =
      function(self, certificate, handshakeSecret, certificateRequest)
        self.__establishedContext.stage = "serverCertificate"
        self:updateTranscriptHash(certificate)

        if certificate.certificateRequestContext ~= "" then
          return self:sendAlert(errors.alert.illegalParameter.detail(
            "server sent Certificate message with non-empty context"
          ))
        end

        if #certificate.certificateList == 0 then
          return self:sendAlert(errors.alert.decodeError.detail(
            "server Certificate message contains empty certificate list"
          ))
        end

        local certificateVerify, err = self:expect("certificateVerify")

        if not certificateVerify then
          return nil, err
        end

        return self:callUnlessCanceled(
          self._hsServerCertificateVerify,
          certificateVerify,
          handshakeSecret,
          certificate,
          certificateRequest
        )
      end,

    _hsServerCertificateVerify = function(
        self, certificateVerify, handshakeSecret,
        certificate, certificateRequest)
      self.__establishedContext.stage = "serverCertificateVerify"

      local signedMessage = ("%s%s%s%s"):format(
        (" "):rep(64),
        "TLS 1.3, server CertificateVerify",
        "\0",
        self:getTranscriptHash()
      )
      local signatureAlgorithm = certificateVerify.algorithm
      local serverCert = certificate.certificateList[1].cert
      local serverPkInfo = serverCert.tbsCertificate.subjectPublicKeyInfo

      self.__establishedContext.serverSignatureAlgorithm = signatureAlgorithm

      local publicKey, err = signatureAlgorithm:decodePublicKey(serverPkInfo)

      if not publicKey then
        return self:sendAlert(
          errors.alert.decryptError.publicKey:wrapping(err, err)
        )
      end

      if not signatureAlgorithm:verify(
            publicKey,
            signedMessage,
            certificateVerify.signature
          ) then
        return self:sendAlert(errors.alert.decryptError.verification())
      end

      self:updateTranscriptHash(certificateVerify)

      local serverFinished, err = self:expect("finished")

      if not serverFinished then
        return nil, err
      end

      return self:callUnlessCanceled(
        self._hsServerFinished,
        serverFinished,
        handshakeSecret,
        certificateRequest
      )
    end,

    _hsServerFinished =
      function(self, finished, handshakeSecret, certificateRequest)
        self.__establishedContext.stage = "serverFinished"

        if self:hasUnreadData() then
          -- a record spans the key change
          return self:sendAlert(
            errors.alert.unexpectedMessage.recordSpansKeyChange()
          )
        end

        local baseKey = handshakeSecret.serverTrafficSecret
        local finishedKey = self:hkdfExpandLabel(
          baseKey,
          "finished",
          "",
          self.__hmac.HASH_SIZE
        )
        local verifyData = self.__hmac(self:getTranscriptHash(), finishedKey)

        if finished.verifyData ~= verifyData then
          return self:sendAlert(errors.alert.decryptError.finished())
        end

        self:updateTranscriptHash(finished)

        local applicationSecret = self:deriveApplicationSecrets(handshakeSecret)
        self:useTrafficKeys("rx", applicationSecret.server)
        applicationSecret.server = nil
        self.__record:setChangeCipherSpecAllowed(false)

        if self.__keyLogFile then
          self.__keyUpdateCount = {
            rx = 0,
            tx = 0,
          }
          self:logApplicationSecret("tx", applicationSecret)
          self:logApplicationSecret("rx", applicationSecret)
        end

        if certificateRequest then
          return self:callUnlessCanceled(
            self._hsClientCertificate,
            certificateRequest,
            handshakeSecret,
            applicationSecret
          )
        else
          return self:callUnlessCanceled(
            self._hsClientFinished, handshakeSecret, applicationSecret
          )
        end
      end,

    _hsClientCertificate = function(
        self, certificateRequest, handshakeSecret, applicationSecret)
      self.__establishedContext.stage = "clientCertificate"

      local signatureAlgorithms = certificateRequest.extensions[
        lib.recognizedExtensions.signatureAlgorithms.type
      ]
      local callbackResult, err = self.__callbacks.onCertificateRequest(
        signatureAlgorithms,
        certificateRequest
      )

      local certificateList

      if callbackResult == false then
        certificateList = {}
      elseif callbackResult == nil then
        return nil, err
      else
        certificateList = {{
          certData = callbackResult.encodedCert,
          extensions = {},
        }}
      end

      local clientCertificate = {
        type = "certificate",

        certificateRequestContext = "",
        certificateList = certificateList,
      }
      local success, err = self:writeMessage(clientCertificate, true)

      if not success then
        return nil, err
      end

      if #certificateList > 0 then
        self.__establishedContext.clientCertificateSent = true

        return self:callUnlessCanceled(
          self._hsClientCertificateVerify,
          callbackResult,
          handshakeSecret,
          applicationSecret
        )
      end

      return self:callUnlessCanceled(
        self._hsClientFinished, handshakeSecret, applicationSecret
      )
    end,

    _hsClientCertificateVerify = function(
        self, callbackResult, handshakeSecret, applicationSecret)
      self.__establishedContext.stage = "clientCertificateVerify"

      local messageToSign = ("%s%s%s%s"):format(
        (" "):rep(64),
        "TLS 1.3, client CertificateVerify",
        "\0",
        self:getTranscriptHash()
      )
      local signatureAlgorithm = callbackResult.algorithm
      local privateKey = callbackResult.privateKey
      local signature = signatureAlgorithm:sign(privateKey, messageToSign)

      self.__establishedContext.clientSignatureAlgorithm = signatureAlgorithm

      local clientCertificateVerify = {
        type = "certificateVerify",

        algorithm = signatureAlgorithm,
        signature = signature,
      }

      local success, err = self:writeMessage(clientCertificateVerify, true)

      if not success then
        return nil, err
      end

      return self:callUnlessCanceled(
        self._hsClientFinished, handshakeSecret, applicationSecret
      )
    end,

    _hsClientFinished = function(self, handshakeSecret, applicationSecret)
      self.__establishedContext.stage = "clientFinished"

      local baseKey = handshakeSecret.clientTrafficSecret
      local finishedKey = self:hkdfExpandLabel(
        baseKey,
        "finished",
        "",
        self.__hmac.HASH_SIZE
      )
      local verifyData = self.__hmac(self:getTranscriptHash(), finishedKey)

      local finished = {
        type = "finished",

        verifyData = verifyData,
      }
      local success, err = self:writeMessage(finished, true)

      if not success then
        return nil, err
      end

      self:useTrafficKeys("tx", applicationSecret.client)
      applicationSecret.client = nil

      return self:_established(applicationSecret)
    end,

    _established = function(self, applicationSecret)
      self.__establishedContext.stage = "established"

      local prevStatus = self.__status
      self.__status = "established"

      if prevStatus == "handshake-canceled" then
        return self:close()
      end

      self.__applicationSecret = applicationSecret

      return true
    end,

    --[[ Post-handshake operations. ]]--

    -- Reads a record of application data.
    read = function(self)
      local rec, err = self:readRecord(
        record.contentTypes.alert,
        record.contentTypes.handshake,
        record.contentTypes.applicationData
      )

      if not rec then
        return nil, err
      elseif rec.type == record.contentTypes.alert then
        return self:_alert(rec)
      elseif rec.type == record.contentTypes.handshake then
        return self:_postHandshakeMessage()
      end

      assert(rec.type == record.contentTypes.applicationData)

      return rec.content
    end,

    -- Writes a record of application data.
    write = function(self, data)
      return self:_writeApplicationData(data)
    end,

    -- Updates client traffic keys and IVs, optionally requesting the same of
    -- the server.
    updateKeys = function(self, requestUpdate)
      self.__applicationSecret =
        self:updateApplicationSecret("tx", self.__applicationSecret)

      local success, err = self:writeMessage({
        type = "keyUpdate",
        requestUpdate = requestUpdate,
      })

      if not success then
        return nil, err
      end

      self:useTrafficKeys("tx", self.__applicationSecret.client)
      self.__applicationSecret.client = nil

      if self.__keyLogFile then
        self.__keyUpdateCount.tx = self.__keyUpdateCount.tx + 1
        self:logApplicationSecret("tx")
      end

      return true
    end,

    -- Returns a copy of the established cryptographic context parameters.
    --
    -- - stage: the current handshake stage
    --
    -- - helloRetried: whether a HelloRetryRequest message was received
    --
    -- - clientCertificateRequested: whether a CertificateRequest message
    --   was received
    --
    -- - clientCertificateSent: whether a client Certificate message was sent
    --
    -- - cipherSuite: the negotiated cipher suite
    --
    -- - namedGroup: the negotiated named group for key exchange
    --
    -- - alpnProtocol: the negotiated application-layer protocol
    --
    -- - serverSignatureAlgorithm: the signature algorithm used by the server
    --
    -- - clientSignatureAlgorithm: the signature algorithm used by the client
    establishedContext = function(self)
      return util.copyMap(self.__establishedContext)
    end,

    _postHandshakeMessage = function(self)
      local message, err = self:expect("newSessionTicket", "keyUpdate")

      if not message then
        return nil, err
      end

      if message.type == "newSessionTicket" then
        return self:_newSessionTicket(message)
      elseif message.type == "keyUpdate" then
        return self:_keyUpdate(message)
      end
    end,

    _nextPostHandshakeMessage = function(self)
      if self:hasUnreadData() then
        return self:_postHandshakeMessage()
      else
        return self:read()
      end
    end,

    _newSessionTicket = function(self, newSessionTicket)
      self.__callbacks.onNewSessionTicket(newSessionTicket)

      return self:_nextPostHandshakeMessage()
    end,

    _keyUpdate = function(self, keyUpdate)
      if self:hasUnreadData() then
        -- a record spans the key change
        return self:sendAlert(
          errors.alert.unexpectedMessage.recordSpansKeyChange()
        )
      end

      self.__applicationSecret =
        self:updateApplicationSecret("rx", self.__applicationSecret)

      if keyUpdate.requestUpdate then
        local success, err = self:updateKeys(false)

        if not success then
          return nil, err
        end
      end

      self:useTrafficKeys("rx", self.__applicationSecret.server)
      self.__applicationSecret.server = nil

      if self.__keyLogFile then
        self.__keyUpdateCount.rx = self.__keyUpdateCount.rx + 1
        self:logApplicationSecret("rx")
      end

      return self:_nextPostHandshakeMessage()
    end,

    _writeApplicationData = function(self, data)
      local success, err = self.__record:write(
        record.contentTypes.applicationData,
        data
      )

      if not success then
        return nil, err
      end

      return #data
    end,
  },
}

function lib.makeSession(args)
  local recordLayer = assert(args.recordLayer)

  local cipherSuites = assert(args.cipherSuites)
  local signatureAlgorithms = assert(args.signatureAlgorithms)
  local certSignatureAlgorithms = assert(args.certSignatureAlgorithms)
  local namedGroups = assert(args.namedGroups)
  local rng = assert(args.rng)

  local callbacks = assert(args.callbacks)
  local keyLogFile = args.keyLogFile

  assert(#cipherSuites > 0)
  assert(#signatureAlgorithms > 0)
  assert(#certSignatureAlgorithms > 0)
  assert(#namedGroups > 0)

  local alpnProtocols = args.alpnProtocols

  if alpnProtocols and #alpnProtocols == 0 then
    alpnProtocols = nil
  end

  local serverNames = args.serverNames

  if serverNames and #serverNames == 0 then
    serverNames = nil
  end

  return setmetatable({
    __record = recordLayer,

    __cipherSuites = cipherSuites,
    __signatureAlgorithms = signatureAlgorithms,
    __certSignatureAlgorithms = certSignatureAlgorithms,
    __namedGroups = namedGroups,
    __rng = rng,

    __hmac = nil,
    __hkdf = nil,
    __aead = nil,

    __callbacks = callbacks,
    __alpnProtocols = alpnProtocols,
    __serverNames = serverNames,

    __keyLogFile = keyLogFile,
    __clientRandom = nil,
    __keyUpdateCount = nil,

    __buf = buffer.makeBuffer(),
    __limits = {},

    __namedGroupCodes = util.sequenceToMap(namedGroups, getCode),
    __signatureAlgorithmCodes =
      util.sequenceToMap(signatureAlgorithms, getCode),
    __certSignatureAlgorithmCodes =
      util.sequenceToMap(certSignatureAlgorithms, getCode),

    __allowedExtensions = {},
    __transcriptHash = nil,
    __emptyStringHash = nil,
    __applicationSecret = nil,

    -- used to track appropriate response to cancellation
    __status = "initial",

    __establishedContext = {
      stage = "clientHello",

      helloRetried = false,
      clientCertificateRequested = false,
      clientCertificateSent = false,

      cipherSuite = nil,
      namedGroup = nil,
      alpnProtocol = nil,
      serverSignatureAlgorithm = nil,
      clientSignatureAlgorithm = nil,
    },
  }, meta)
end

return lib

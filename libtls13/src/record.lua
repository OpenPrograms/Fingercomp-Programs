-- The TLS record layer.

local errors = require("tls13.error")
local utilMap = require("tls13.util.map")

local lib = {}

lib.contentTypes = utilMap.makeBijectiveMap {
  changeCipherSpec = 20,
  alert = 21,
  handshake = 22,
  applicationData = 23,
}

lib.closureAlerts = utilMap.makeBijectiveMap {
  closeNotify = 0,
  userCanceled = 90,
}

local MAX_CIPHERTEXT_LENGTH = (1 << 14) + 256
local MAX_PLAINTEXT_LENGTH = 1 << 14

local TLS_LEGACY_VERSION = 0x0303
lib.TLS_LEGACY_VERSION = TLS_LEGACY_VERSION

local meta = {
  __index = {
    read = function(self)
      local contentType, version, length = self.__sock:readUnpack(">BI2I2")

      if not contentType then
        return nil, version
      end

      if length > MAX_CIPHERTEXT_LENGTH then
        return self:sendAlert(errors.alert.recordOverflow.ciphertext(
          length, MAX_CIPHERTEXT_LENGTH
        ))
      end

      local content, err = self.__sock:read(length)

      if not content then
        return nil, err
      end

      local record = {
        type = contentType,
        version = version,
        content = content
      }

      if record.type == lib.contentTypes.changeCipherSpec then
        return self:_decodeChangeCipherSpec(record)
      end

      if record.type ~= lib.contentTypes.alert
          and record.type ~= lib.contentTypes.handshake
          and record.type ~= lib.contentTypes.applicationData then
        return self:sendAlert(
          errors.alert.unexpectedMessage.unknownContentType(record.type)
        )
      end

      record, err = self:_deprotect(record)

      if not record then
        return nil, err
      elseif record.type == lib.contentTypes.changeCipherSpec then
        return self:sendAlert(
          errors.alert.unexpectedMessage.protectedChangeCipherSpec()
        )
      elseif record.type == lib.contentTypes.alert then
        return self:_decodeAlert(record)
      elseif record.type ~= lib.contentTypes.applicationData
          and record.type ~= lib.contentTypes.handshake then
        return self:sendAlert(
          errors.alert.unexpectedMessage.unknownContentType(record.type)
        )
      end

      self.__rx.seq = self.__rx.seq + 1

      return record
    end,

    write = function(self, contentType, message)
      local parts = {}

      for i = 1, #message, MAX_PLAINTEXT_LENGTH do
        table.insert(parts, message:sub(i, i + MAX_PLAINTEXT_LENGTH - 1))
      end

      local records = {}

      for i, part in ipairs(parts) do
        records[i], err = self:_protect({
          content = part,
          type = contentType,
          padding = 0,
        })

        if not records[i] then
          return nil, err
        end

        self.__tx.seq = self.__tx.seq + 1
      end

      for i, record in ipairs(records) do
        records[i] = (">B I2 s2"):pack(
          record.type,
          TLS_LEGACY_VERSION,
          record.content
        )
      end

      return self.__sock:write(table.concat(records))
    end,

    sendAlert = function(self, alert)
      local alertCode

      if type(alert) == "number" then
        alertCode = alert
        alert = errors.alert.unknownAlert(alertCode)
      else
        assert(alert.CATEGORY == "alert")
        alertCode = assert(
          errors.alert[alert.KEY].NUM,
          "unknown alert"
        )
      end

      local closureAlert = lib.closureAlerts[alertCode]
      local message = ("BB"):pack(closureAlert and 1 or 2, alertCode)
      local result, err = self:write(lib.contentTypes.alert, message)

      if not result then
        return nil, err
      end

      if closureAlert then
        return nil, errors.tls.localCloseAlert:wrapping(alert, alert)
      end

      self.__alertSent = true
      self:close()

      return nil, errors.tls.localAlert:wrapping(alert, alert)
    end,

    close = function(self)
      return self.__sock:close()
    end,

    changeKeys = function(self, side, aead, iv)
      local newContext = {
        seq = 0,
        aead = aead,
        iv = iv,
      }

      if side == "rx" then
        self.__rx = newContext
      elseif side == "tx" then
        self.__tx = newContext
      else
        error("unknown side: " .. side)
      end
    end,

    setChangeCipherSpecAllowed = function(self, allowed)
      self.__changeCipherSpecAllowed = allowed
    end,

    fatalAlertSent = function(self)
      return self.__alertSent
    end,

    _protect = function(self, record)
      if not self.__tx.aead then
        return record
      end

      local innerPlaintext = ("%s%s%s"):format(
        record.content,
        string.char(record.type),
        ("\0"):rep(record.padding)
      )

      local aadFmt = ">B I2 I2"
      local length = self.__tx.aead:getLength(
        #innerPlaintext,
        string.packsize(aadFmt)
      )
      assert(length <= (1 << 14) + 256)

      local aad = aadFmt:pack(
        lib.contentTypes.applicationData,
        TLS_LEGACY_VERSION,
        length
      )

      local nonce = self:_generateNonce(self.__tx)

      local encryptedRecord = self.__tx.aead:encrypt(
        innerPlaintext,
        nonce,
        aad
      )

      return {
        type = lib.contentTypes.applicationData,
        content = encryptedRecord,
      }
    end,

    _deprotect = function(self, record)
      if not self.__rx.aead then
        return record
      end

      local aad = (">B I2 I2"):pack(
        record.type,
        record.version,
        #record.content
      )
      local nonce = self:_generateNonce(self.__rx)
      local plaintext, err = self.__rx.aead:decrypt(
        record.content,
        nonce,
        aad
      )

      if not plaintext then
        return self:sendAlert(errors.alert.badRecordMac())
      end

      if #plaintext > MAX_PLAINTEXT_LENGTH + 1 then
        return self:sendAlert(errors.alert.recordOverflow.plaintext(
          #plaintext, MAX_PLAINTEXT_LENGTH
        ))
      end

      local content, contentTypeByte = plaintext:match("^(.-)([^\0])\0*$")

      if not content then
        return self:sendAlert(errors.alert.unexpectedMessage.noNonZeroByte())
      end

      local contentType = contentTypeByte:byte()

      return {
        type = contentType,
        content = content,
      }
    end,

    _generateNonce = function(self, ctx)
      local iv = (">I8"):unpack(ctx.iv:sub(-8))
      local nonce = ctx.iv:sub(1, -9) .. (">I8"):pack(iv ~ ctx.seq)

      return nonce
    end,

    _decodeChangeCipherSpec = function(self, record)
      if not self.__changeCipherSpecAllowed then
        return self:sendAlert(errors.alert.unexpectedMessage.changeCipherSpec())
      end

      if record.content ~= "\x01" then
        return seld:sendAlert(
          errors.alert.unexpectedMessage.changeCipherSpecContent()
        )
      end

      -- ignore and read the next record (via tail recursion for clarity)
      return self:read()
    end,

    _decodeAlert = function(self, record)
      if #record.content ~= 2 then
        return self:sendAlert(errors.alert.decodeError.detail(
          "alert body length must be 2"
        ))
      end

      local level, alertCode = ("BB"):unpack(record.content)
      local alertKey =
        errors.alertEncoding[alertCode]
        or "unknownAlert"
      local alert = errors.alert[alertKey]()

      if lib.closureAlerts[alertCode] then
        alert = errors.tls.remoteCloseAlert:wrapping(alert, alert)
      else
        alert = errors.tls.remoteAlert:wrapping(alert, alert)
      end

      record.alert = alert

      return record
    end,
  },
}

function lib.makeRecordLayer(sock)
  return setmetatable({
    __sock = sock,
    __rx = {
      seq = 0,
      aead = nil,
      iv = nil,
    },
    __tx = {
      seq = 0,
      aead = nil,
      iv = nil,
    },
    __changeCipherSpecAllowed = false,
    __alertSent = false,
  }, meta)
end

return lib

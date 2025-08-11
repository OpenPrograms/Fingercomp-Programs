-- A decoder for ASN.1 data encoded using the DER.
--
-- Ref:
-- - ITU-T X.690. https://www.itu.int/rec/T-REC-X.690

local bitstring = require("tls13.asn.bitstring")
local buffer = require("tls13.buffer")
local errors = require("tls13.error")
local util = require("tls13.util")

local lib = {}

lib.asnTags = {
  universal = {},
  application = {},
  contextSpecific = {},
  private = {},
}

do
  local meta = {
    __index = function(self, key)
      if type(key) == "string" then
        local result = util.copy(self)
        table.insert(result, key .. "(<unspecified>)")

        return setmetatable(result, {
          __call = function(_, component)
            self[key] = self / component

            return self[key]
          end,

          __tostring = function(this)
            return ("%s / %s"):format(self, this[#this])
          end,
        })
      end
    end,

    __eq = function(self, other)
      if getmetatable(self) ~= getmetatable(other) or #self ~= #other then
        return false
      end

      for i, component in ipairs(self) do
        if other[i] ~= component then
          return false
        end
      end

      return true
    end,

    __div = function(self, components)
      local subOid = util.copy(self)

      if type(components) == "number" then
        table.insert(subOid, components)
      else
        table.move(components, 1, #components, #subOid + 1, subOid)
      end

      return setmetatable(subOid, getmetatable(self))
    end,

    __tostring = function(self)
      return table.concat(self, ".")
    end,

    __call = function(self, component)
      assert(self[#self] == component, "invalid OID component")

      return self
    end,
  }

  function lib.makeOid(...)
    local components = ...

    if type(components) ~= "table" then
      components = {...}
    end

    return setmetatable(components, meta)
  end
end

local tagSpecMeta = {
  __index = {
    label = function(self)
      if self.shortName then
        return self.shortName
      else
        return tostring(self)
      end
    end,
  },

  __tostring = function(self)
    if self.name then
      return self.name
    elseif self.class == "contextSpecific" then
      return ("[%d]"):format(self.num)
    else
      return ("[%s %d]"):format(self.class:upper(), self.num)
    end
  end,

  __eq = function(self, other)
    return getmetatable(other) == getmetatable(self)
      and self.class == other.class and self.num == other.num
  end,
}

function lib.makeTagSpec(class, num, name, shortName)
  shortName = shortName or name

  return setmetatable({
    class = class,
    num = num,
    name = name,
    shortName = shortName,
  }, tagSpecMeta)
end

function lib.registerAsnTag(class, num, name, shortName, key)
  if type(class) ~= "string" then
    class, num, name, shortName, key =
      "universal", class, num, name, shortName
  end

  key = key or name:lower():gsub("%s+(.)", string.upper)

  assert(
    lib.asnTags[class][num] == nil,
    ("duplicate tag %s/%x"):format(class, num)
  )
  assert(
    lib.asnTags[class][key] == nil,
    ("duplicate tag key %s/%s"):format(class, key)
  )

  local tagSpec = lib.makeTagSpec(class, num, name, shortName)
  tagSpec.key = key

  lib.asnTags[class][num] = tagSpec
  lib.asnTags[class][key] = tagSpec
end

lib.registerAsnTag(1, "BOOLEAN", "BOOL")
lib.registerAsnTag(2, "INTEGER", "INT")
lib.registerAsnTag(3, "BIT STRING", "BITS")
lib.registerAsnTag(4, "OCTET STRING", "BYTES")
lib.registerAsnTag(5, "NULL")
lib.registerAsnTag(6, "OBJECT IDENTIFIER", "OID")
lib.registerAsnTag(10, "ENUMERATED", "ENUM")
lib.registerAsnTag(12, "UTF8String", "UTF8", "utf8String")
lib.registerAsnTag(16, "SEQUENCE", "SEQ")
lib.registerAsnTag(17, "SET")
lib.registerAsnTag(18, "NumericString", "NUMSTR", "numericString")
lib.registerAsnTag(19, "PrintableString", "PRSTR", "printableString")
lib.registerAsnTag(20, "TeletexString", "T61STR", "teletexString")
lib.registerAsnTag(22, "IA5String", "IA5STR", "ia5String")
lib.registerAsnTag(23, "UTCTime", "UTIME", "utcTime")
lib.registerAsnTag(24, "GeneralizedTime", "GTIME", "generalizedTime")
lib.registerAsnTag(25, "GraphicString", "GRSTR", "graphicString")
lib.registerAsnTag(26, "VisibleString", "ISO646STR", "visibleString")
lib.registerAsnTag(27, "GeneralString", "GENSTR", "generalString")
lib.registerAsnTag(28, "UniversalString", "UNISTR", "universalString")
lib.registerAsnTag(30, "BMPString", "BMPSTR", "bmpString")

lib.tagParsers = {}

lib.tagParsers[lib.asnTags.universal.boolean] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.invalidEncoding, context.encoding
    )
  end

  local byte, err = buf:readU8()

  if not byte then
    return nil, err
  end

  if byte == 0x00 then
    return context:makeValue({false}, buf:pos())
  elseif byte == 0xff then
    return context:makeValue({true}, buf:pos())
  end

  return nil, buf:makeParserError(errors.asn.invalidBooleanValue, byte)
end

lib.tagParsers[lib.asnTags.universal.integer] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.invalidEncoding, context.encoding
    )
  end

  local length = math.max(context.length, 1)

  if length > 1 then
    local byte1, byte2 = buf:peek(1, 2):byte(1, 2)
    local firstBits = byte1 << 1 | byte2 >> 7

    if firstBits == 0x1ff or firstBits == 0x000 then
      return nil, buf:makeParserError(errors.asn.overlongEncoding)
    end
  end

  local int, err = buf:readInt(length, true)

  if not int then
    return nil, err
  end

  return context:makeValue({
    long = type(int) == "table",

    int,
  }, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.bitString] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.derConstructedForbidden,
      context.tagSpec.class, context.tagSpec.name
    )
  end

  local length = math.max(context.length, 1) - 1

  local unusedBitCount = buf:readU8()

  if unusedBitCount >= 8 then
    return nil, buf:makeParserError(
      errors.asn.tooManyUnusedBits, unusedBitCount
    )
  end

  local bytes, err = buf:read(length)

  if not bytes then
    return nil, err
  end

  if #bytes > 0 then
    local lastByte = bytes:byte(-1)

    if lastByte & ((1 << unusedBitCount) - 1) ~= 0 then
      return nil, buf:makeParserError(errors.asn.nonZeroUnusedBits)
    end
  end

  local bigint = bitstring.fromBytes(bytes, unusedBitCount)

  return context:makeValue({bigint}, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.octetString] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.derConstructedForbidden, context.tagSpec
    )
  end

  local bytes, err = buf:read(context.length)

  if not bytes then
    return nil, err
  end

  return context:makeValue({bytes}, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.null] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.invalidEncoding, context.encoding
    )
  end

  return context:makeValue({}, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.objectIdentifier] = function(buf, context)
  if context.encoding ~= "primitive" then
    return nil, buf:makeParserError(
      errors.asn.invalidEncoding, context.encoding
    )
  end

  local components = {-1}
  local startPos = buf:pos()

  repeat
    local subid, err = buf:readVarint(true)

    if not subid then
      return nil, err
    end

    table.insert(components, subid)
  until buf:pos() >= startPos + context.length

  if components[2] < 40 then
    components[1] = 0
  elseif components[2] < 80 then
    components[1], components[2] = 1, components[2] - 40
  else
    components[1], components[2] = 2, components[2] - 80
  end

  return context:makeValue({lib.makeOid(components)}, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.enumerated] =
  lib.tagParsers[lib.asnTags.universal.integer]
lib.tagParsers[lib.asnTags.universal.utf8String] =
  lib.tagParsers[lib.asnTags.universal.octetString]

lib.tagParsers[lib.asnTags.universal.sequence] = function(buf, context)
  if context.encoding ~= "constructed" then
    return nil, buf:makeParserError(
      errors.asn.invalidEncoding, context.encoding
    )
  end

  local values = {}
  local startPos = buf:pos()

  while buf:pos() < startPos + context.length do
    local value, err = lib.parseAsnValue(buf)

    if not value then
      return nil, err
    end

    table.insert(values, value)
  end

  return context:makeValue(values, buf:pos())
end

lib.tagParsers[lib.asnTags.universal.set] =
  lib.tagParsers[lib.asnTags.universal.sequence]
lib.tagParsers[lib.asnTags.universal.numericString] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.printableString] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.teletexString] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.ia5String] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.graphicString] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.visibleString] =
  lib.tagParsers[lib.asnTags.universal.octetString]
lib.tagParsers[lib.asnTags.universal.utcTime] =
  lib.tagParsers[lib.asnTags.universal.visibleString]
lib.tagParsers[lib.asnTags.universal.generalizedTime] =
  lib.tagParsers[lib.asnTags.universal.visibleString]
lib.tagParsers[lib.asnTags.universal.bmpString] =
  lib.tagParsers[lib.asnTags.universal.octetString]

function lib.defaultTagParser(buf, context)
  if context.encoding == "primitive" then
    local contents, err = buf:read(context.length)

    if not contents then
      return nil, err
    end

    return context:makeValue({
      CONTENTS = contents,

      contents,
    }, buf:pos())
  end

  local components = {}
  local startPos = buf:pos()
  local contents = buf:peek(1, context.length)

  while buf:pos() < startPos + context.length do
    local component, err = lib.parseAsnValue(buf)

    if not component then
      return nil, err
    end

    table.insert(components, component)
  end

  components.CONTENTS = contents

  return context:makeValue(components, buf:pos())
end

local makeContext do
  local meta = {
    __index = {
      makeValue = function(self, value, pos)
        value.TAG = self.tagSpec
        value.ENCODING = self.encoding
        value.LENGTH = self.length
        value.START = self.start
        value.END = pos - 1

        return value
      end,
    },
  }

  function makeContext(fields)
    return setmetatable(fields, meta)
  end
end

local function parseAsnId(buf)
  local id, err = buf:readU8()

  if not id then
    return nil, err
  end

  local class = id >> 6
  local encoding = id & 0x20
  local tagNumber = id & 0x1f

  if class == 0 then
    class = "universal"
  elseif class == 1 then
    class = "application"
  elseif class == 2 then
    class = "contextSpecific"
  elseif class == 3 then
    class = "private"
  end

  if encoding == 0 then
    encoding = "primitive"
  else
    encoding = "constructed"
  end

  if tagNumber == 0x1f then
    tagNumber, err = buf:withContext("tag id", function()
      return buf:readVarint(true)
    end)

    if not tagNumber then
      return nil, err
    end
  end

  return class, encoding, tagNumber
end

local function parseAsnLength(buf)
  return buf:withContext("len", function()
    local length, err = buf:readU8()

    if not length then
      return nil, err
    end

    if length & 0x80 == 0 then
      return length
    elseif length == 0x80 then
      return "indefinite"
    elseif length == 0xff then
      return nil, buf:makeParserError(errors.asn.reservedLength)
    end

    if buf:peek() == "\0" then
      return nil, buf:makeParserError(errors.asn.overlongEncoding)
    end

    length, err = buf:readInt(length ~ 0x80)

    if not length then
      return nil, err
    elseif type(length) == "table" then
      -- err is the length size
      return nil, buf:makeParserError(errors.asn.valueTooLong, err)
    end

    if length < 0x80 then
      return nil, buf:makeParserError(errors.asn.overlongEncoding)
    end

    return length
  end)
end

function lib.parseAsnValue(buf)
  local pos = buf:pos()
  local class, encoding, tagNumber = parseAsnId(buf)

  if not class then
    return nil, encoding
  end

  local tagSpec = lib.asnTags[class][tagNumber]

  if not tagSpec then
    tagSpec = lib.makeTagSpec(class, tagNumber)
  end

  return buf:withContext(tagSpec:label(), function()
    local lengthPos = buf:pos()
    local length, err = parseAsnLength(buf)
    local contentsStart = buf:pos()

    if not length then
      return nil, err
    end

    if length == "indefinite" then
      return nil, buf:makeParserError(errors.asn.derIndefiniteForbidden)
    end

    local tagParser = lib.tagParsers[tagSpec] or lib.defaultTagParser

    local result, err = buf:withLimit(length, function()
      local context = makeContext {
        tagSpec = tagSpec,
        encoding = encoding,
        length = length,
        start = pos,
      }

      return tagParser(buf, context)
    end, lengthPos)

    if not result then
      return nil, err
    end

    if buf:pos() < contentsStart + length - 1 then
      return nil, buf:makeParserError(
        errors.asn.trailingValueBytes,
        length, buf:pos() - contentsStart
      )
    end

    return result
  end, pos)
end

function lib.parseImplicitTag(tag, tagSpec, context)
  local buf = buffer.makeBuffer(tag.CONTENTS)

  if context then
    for _, component in ipairs(context) do
      buf:pushContext(component)
    end
  end

  local context = makeContext {
    tagSpec = tagSpec,
    encoding = tag.ENCODING,
    length = tag.LENGTH,
    start = tag.START,
  }
  local tagParser = lib.tagParsers[tagSpec] or lib.defaultTagParser

  return buf:withContext(("%s IMPLICIT %s"):format(tag.TAG, tagSpec), function()
    local result, err = tagParser(buf, context)

    if not result then
      return nil, err
    end

    if buf:pos() < tag.LENGTH + 1 then
      return nil, buf:makeParserError(
        errors.asn.trailingValueBytes,
        tag.LENGTH, buf:pos()
      )
    end

    return result
  end)
end

function lib.decode(asn, allowTrailingData, context)
  local buf = buffer.makeBuffer(asn)

  if context then
    for _, component in ipairs(context) do
      buf:pushContext(component)
    end
  end

  local value, err = lib.parseAsnValue(buf)

  if not value then
    return nil, err
  end

  if not allowTrailingData then
    local result, err = buf:expectEof()

    if not result then
      return nil, err
    end
  end

  return value
end

return lib

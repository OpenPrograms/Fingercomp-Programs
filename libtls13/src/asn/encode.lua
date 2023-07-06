-- Utilities for encoding ASN.1 values.

local asn = require("tls13.asn")
local util = require("tls13.util")

local lib = {}

function lib.encodeAsnValue(tag, encoding, contents)
  -- it's not even hard to support them, but I don't need that, so I don't.
  assert(tag.num < 0x1f, "long tags are not supported")

  local length = #contents
  local initialOctet = tag.num

  if encoding == "primitive" then
    -- do nothing, pretty much.
  elseif encoding == "constructed" then
    initialOctet = initialOctet | 0x20
  else
    error("unknown encoding: " .. encoding)
  end

  if tag.class == "universal" then
    -- do nothing
  elseif tag.class == "application" then
    initialOctet = initialOctet | 0x40
  elseif tag.class == "contextSpecific" then
    initialOctet = initialOctet | 0x80
  elseif tag.class == "private" then
    initialOctet = initialOctet | 0xc0
  else
    error("unknown class: " .. tag.class)
  end

  if length < 0x80 then
    return (">B s1"):pack(initialOctet, contents)
  end

  local lengthSize = util.idivCeil(util.lastLeadingZero(length), 8)
  assert(lengthSize < 0x7f, "size is too large")

  return (">B B I" .. lengthSize):pack(
    initialOctet,
    0x80 | lengthSize,
    length
  ) .. contents
end

function lib.encodeVarint(n)
  local bytes = {}

  repeat
    local byte = n & 0x7f

    if #bytes > 0 then
      byte = byte | 0x80
    end

    table.insert(bytes, ("B"):pack(byte))
    n = n >> 7
  until n == 0

  -- swap bytes (varints are big-endian)
  util.reverse(bytes)

  return table.concat(bytes)
end

function lib.encodeObjectIdentifier(oid)
  oid = util.copy(oid)
  local firstComponent = table.remove(oid, 1)
  oid[1] = oid[1] + firstComponent * 40

  for i = 1, #oid, 1 do
    oid[i] = lib.encodeVarint(oid[i])
  end

  return lib.encodeAsnValue(
    asn.asnTags.universal.objectIdentifier,
    "primitive",
    table.concat(oid)
  )
end

function lib.encodeSequence(values)
  return lib.encodeAsnValue(
    asn.asnTags.universal.sequence,
    "constructed",
    table.concat(values)
  )
end

function lib.encodeOctetString(s)
  return lib.encodeAsnValue(
    asn.asnTags.universal.octetString,
    "primitive",
    s
  )
end

function lib.encodeNull()
  return lib.encodeAsnValue(
    asn.asnTags.universal.null,
    "primitive",
    ""
  )
end

function lib.encodeBitString(bits)
  return lib.encodeAsnValue(
    asn.asnTags.universal.bitString,
    "primitive",
    string.char(bits:padding() & 0x7) .. bits:toBytes()
  )
end

return lib

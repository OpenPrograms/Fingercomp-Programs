-- Copyright 2016 Fingercomp

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--     http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- An implementation of DER decoder.

local comp = require("computer")

local bigint = require("bigint")

local function read(s, len)
  local result = s[0]:sub(1, len)
  s[0] = s[0]:sub(len + 1, -1)
  return result
end

local function decodeID(s)
  local data = read(s, 1):byte()
  local tag = data & 0x1f
  data = data >> 5
  local pc = data & 0x1
  local class = data >> 1
  if tag ~= 0x1f then
    return {
      tag = tag,
      pc = pc,
      class = class
    }
  else
    tag = 0x0
    repeat
      data = read(s, 1):byte()
      tag = (tag << 7) | (data & 0x7f)
    until data < 128
    return {
      tag = tag,
      pc = pc,
      class = class
    }
  end
end

local function decodeLen(s)
  local data = read(s, 1):byte()
  if data == 0x80 then
    error("DER doesn't allow indefinite length")
    -- return "eoc"
  elseif data == 0xff then
    return false
  elseif data >> 7 == 0 then
    return data & 0x7f
  else
    local bytes = data & 0x7f
    local len = 0x0
    for i = 1, bytes, 1 do
      data = read(s, 1):byte()
      len = (len << 8) | data
    end
    return len
  end
end

local function getNextEOC(s, len)
  if len ~= "eoc" then return len end
  error("DER doesn't allow indefinite length")
  -- local buf = {s[0]}
  -- len = 0
  -- while true do
  --   if buf[0]:sub(1, 2) == "\x00\x00" then
  --     break
  --   end
  --   local data = read(buf, 1)
  --   len = len + 1
  -- end
  -- return len
end

local function bitlen(num)
  return math.ceil(math.log(num, 2))
end

local decode

local decoders = {}

decoders[0x01] = function(s, id, len) -- BOOLEAN
  len = getNextEOC(s, len)
  assert(id.pc == 0, "BOOLEAN shall be primitive")
  assert(len == 1, "BOOLEAN must have content of length 1")
  local data = read(s, len):byte()
  if data == 0x00 then
    return false
  elseif data == 0xff then
    return true
  else
    error("unexpected BOOLEAN content: should be either 0x00 or 0xff")
  end
end

decoders[0x02] = function(s, id, len) -- INTEGER
  len = getNextEOC(s, len)
  assert(id.pc == 0x0, "INTEGER shall be primitive")
  assert(len > 0, "INTEGER must have content of length ≥ 1")
  local firstByte = s[0]:sub(1, 1):byte()
  if len > 1 then
    local second8Bit = s[0]:sub(2, 2):byte() >> 7
    assert(not (firstByte == 0xff and second8Bit == 1 or firstByte == 0x00 and second8Bit == 0), "invalid value: first 9 bits are " .. second8Bit)
  end
  local result = len < 46.5 and 0 or bigint(0)
  if (s[0]:sub(1, 1):byte() >> 7) == 1 then
    result = len < 46.5 and -1 or bigint(-1)
  end
  for i = 1, len, 1 do
    result = (result * 256) + read(s, 1):byte()
  end
  return result
end

decoders[0x0a] = function(s, id, len) -- ENUMERATED
  return decoders[0x02](s, id, len)
end

decoders[0x09] = function(s, id, len) -- REAL
  len = getNextEOC(s, len)
  if len == 0 then
    return 0.0
  end
  local bl2 = s[0]:sub(1, 1):byte() >> 6
  local b8, b7 = bl2 >> 1, bl2 & 0x1
  if b8 == 1 then -- binary
    local firstByte = read(s, 1):byte()
    len = len - 1
    local exptype = firstByte & 0x03
    local f = (firstByte >> 2) & 0x03
    local b = (firstByte >> 4) & 0x03
    if b == 0x03 then
      error("Value 0x03 of base is reserved!")
    end
    local sign = -((firstByte >> 6) & 0x01)
    if exptype == 0x03 then
      exptype = read(s, 1):byte() + 1
      len = len - 1
      if exptype == 1 then
        error("Exponent length must not be 1 if E encoding type 0x03 is used!")
      end
      if ({[0x00]=true, [0x1ff]=true})[(s[0]:sub(1, 1):byte() << 1) + (s[0]:sub(2, 2):byte() & 0x01)] then
        error("Exponent must not have 9 bits of 1 or 0!")
      end
    end
    explen = exptype + 1
    expstr = read(s, explen)
    len = len - explen
    exp = 0
    for i = 1, #expstr, 1 do
      exp = (exp << 8) | expstr:sub(i, i):byte()
    end
    if b == 0x01 then
      exp = exp * 3
    elseif b == 0x02 then
      exp = exp * 4
    end
    local n = 0
    for i = 1, len, 1 do
      n = (n << 8) | read(s, 1):byte()
    end
    return s * n * 2^exp
  elseif b8 == 0 and b7 == 0 then -- decimal
    local firstByte = read(s, 1):byte()
    local bytes = read(s, len):byte()
    local result = 0
    for i = 1, #bytes, 1 do
      result = (result << 8) | read(s, 1):byte()
    end
    return result
  elseif b8 == 0 and b7 == 1 then -- specialreal
    if len ~= 1 then
      error("SpecialReal must have a contents of length 1")
    end
    local firstByte = read(s, 1)
    if firstByte == 0x40 then
      return math.huge
    elseif firstByte == 0x41 then
      return -math.huge
    end
  end
end

decoders[0x03] = function(s, id, len) -- BIT STRING
  if id.pc == 1 then -- constructed
    error("DER doesn't allow constructed strings")
    -- local data = 0
    -- local lenleft = len
    -- while true do
    --   local prevlen = 0
    --   if len ~= "eoc" then
    --     prevlen = #s[0]
    --   end
    --   local decoded = decode(s, {sametag = id.tag})
    --   if len ~= "eoc" then
    --     lenleft = lenleft - (prevlen - #s[0])
    --   end
    --   data = (data << bitlen(decoded)) | decoded
    --   if len ~= "eoc" then
    --     if lenleft == 0 then
    --       break
    --     elseif lenleft < 0 then
    --       error("Corrupt data: contents length is more than length of container")
    --     end
    --   else
    --     if s[0]:sub(1, 2) == "\x00\x00" then
    --       read(s, 2) -- read EOC
    --       break
    --     end
    --   end
    -- end
  else -- primitive
    len = getNextEOC(s, len)
    local rShift = read(s, 1):byte()
    local data = read(s, len - 1)
    local result = {}
    for i = 1, #data, 1 do
      result[#result+1] = ("%02X"):format(data:sub(i, i):byte())
    end
    for i = 1, rShift, 1 do
      local bovr = 0
      for j = #result, 1, -1 do
        local byte = tonumber(result[j], 16) + bovr
        result[j] = ("%02X"):format(byte // 2)
        bovr = (byte % 2) * 100
      end
    end
    return table.concat(result):gsub("%x%x", function(n)
      return string.char(tonumber(n, 16))
    end)
  end
end

decoders[0x04] = function(s, id, len) -- OCTET STRING
  if id.pc == 1 then -- constructed
    error("DER doesn't allow constructed strings")
    -- local data = 0
    -- local lenleft = len
    -- while true do
    --   local prevlen = 0
    --   if len ~= "eoc" then
    --     prevlen = #s[0]
    --   end
    --   local decoded = decode(s, {sametag = id.tag})
    --   data = (data << 8) | decoded
    --   if len ~= "eoc" then
    --     lenleft = lenleft - (prevlen - #s[0])
    --   end
    --   if len ~= "eoc" then
    --     if lenleft == 0 then
    --       break
    --     elseif lenleft < 0 then
    --       error("Corrupt data: contents length is more than length of container")
    --     end
    --   else
    --     if s[0]:sub(1, 2) == "\x00\x00" then
    --       read(s, 2) -- read EOC
    --       break
    --     end
    --   end
    -- end
    -- return data
  else -- primitive
    len = getNextEOC(s, len)
    return read(s, len)
  end
end

decoders[0x05] = function(s, id, len) -- NULL
  len = getNextEOC(s, len)
  assert(id.pc == 0, "NULL shall be primitive")
  assert(len == 0, "NULL must not have a content")
  return nil
end

decoders[0x10] = function(s, id, len, kwargs) -- SEQUENCE & SEQUENCE OF
  assert(id.pc == 1, "SEQUENCE shall be constructed")
  local result = {}
  local lenleft = len
  while true do
    local prevlen = 0
    if len ~= "eoc" then
      prevlen = #s[0]
    end
    local decoded = decode(s, kwargs)
    result[#result+1] = decoded
    -- print("P", prevlen, #s[0], lenleft, len)
    if len ~= "eoc" then
      lenleft = lenleft - (prevlen - #s[0])
    end
    -- print("P2", lenleft)
    if len ~= "eoc" then
      if lenleft == 0 then
        break
      elseif lenleft < 0 then
        error("Corrupt data: contents length is more than length of container")
      end
    else
      if s[0]:sub(1, 2) == "\x00\x00" then
        read(s, 2) -- read EOC
        break
      end
    end
  end
  return result
end

decoders[0x11] = function(s, id, len, kwargs) -- SET & SET OF
  assert(id.pc == 1, "SET shall be constructed")
  local result = {}
  local lenleft = len
  while true do
    local prevlen = 0
    if len ~= "eoc" then
      prevlen = #s[0]
    end
    local decoded = decode(s, kwargs)
    result[#result+1] = decoded
    if len ~= "eoc" then
      lenleft = lenleft - (prevlen - #s[0])
    end
    if len ~= "eoc" then
      if lenleft == 0 then
        break
      elseif lenleft < 0 then
        error("Corrupt data: contents length is more then length of container")
      end
    else
      if s[0]:sub(1, 2) == "\x00\x00" then
        read(s, 2) -- read EOC
        break
      end
    end
  end
  return result
end

decoders[0x06] = function(s, id, len) -- OBJECT IDENTIFIER
  assert(id.pc == 0, "OBJECT IDENTIFIER shall be primitive")
  len = getNextEOC(s, len)
  local result = {}
  for i = 1, len, 1 do
    local byte = read(s, 1):byte()
    if byte == 0x80 then
      error("The leading byte is of value 0x80, which is not allowed")
    end
    if #result == 0 then result = {false} end
    result[#result] = ((result[#result] or 0) << 7) | (byte & 0x7f)
    if byte >> 7 == 0 then
      result[#result+1] = false
    end
  end
  if result[#result] == false then
    result[#result] = nil
  end
  return result
end

decoders[0x0D] = function(s, id, len) -- RELATIVE OBJECT IDENTIFIER
  assert(id.pc == 0, "RELATIVE OBJECT IDENTIFIER shall be primitive, but it isn't")
  return decoders[0x06](s, id, len)
end

decoders[0x0c] = function(s, id, len) -- UTF8String
  assert(id.pc == 0, "DER requires UTF8String to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x12] = function(s, id, len) -- NumericString
  assert(id.pc == 0, "DER requires NumericString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x13] = function(s, id, len) -- PrintableString
  assert(id.pc == 0, "DER requires PrintableString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x14] = function(s, id, len) -- T61String
  assert(id.pc == 0, "DER requires T61String to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x15] = function(s, id, len) -- VideotexString
  assert(id.pc == 0, "DER requires VideotexString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x16] = function(s, id, len) -- IA5String
  assert(id.pc == 0, "DER requires IA5String to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x17] = function(s, id, len) -- UTCTime
  assert(id.pc == 0, "DER requires UTCTime to be primitive, but it isn't")
  len = getNextEOC(s, len)
  local data = read(s, len)
  local year, month, day, hour, min, sec = data:match("^(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)Z$")
  if not year then
    error("Corrupt data: time pattern not matched")
  end
  year = tonumber(year)
  if year >= 50 then
    year = 1900 + year
  else
    year = 2000 + year
  end
  return {
    year = tonumber(year),
    month = tonumber(month),
    day = tonumber(day),
    hour = tonumber(hour),
    minute = tonumber(min),
    second = tonumber(sec)
  }
end

decoders[0x18] = function(s, id, len) -- GeneralizedTime
  assert(id.pc == 0, "DER requires GeneralizedTime to be primitive, but it isn't")
  len = getNextEOC(s, len)
  local data = read(s, len)
  local year, month, day, hour, min, sec, fr = data:match("^(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(.*)Z$")
  if not year then
    error("Corrupt data: time pattern not matched")
  end
  if not fr:match("^%.(%d+)$") then
    error("Corrupt data: time pattern not matched")
  end
  return {
    year = tonumber(year),
    month = tonumber(month),
    day = tonumber(day),
    hour = tonumber(hour),
    minute = tonumber(min),
    second = tonumber(sec)
  }
end

decoders[0x19] = function(s, id, len) -- GraphicString
  assert(id.pc == 0, "DER requires GraphicString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x1a] = function(s, id, len) -- VisibleString
  assert(id.pc == 0, "DER requires VisibleString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x1b] = function(s, id, len) -- GeneralString
  assert(id.pc == 0, "DER requires GeneralString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x1c] = function(s, id, len) -- UniversalString
  assert(id.pc == 0, "DER requires UniversalString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x1d] = function(s, id, len) -- CHARACTER STRING
  assert(id.pc == 0, "DER requires CHARACTER STRING to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

decoders[0x1e] = function(s, id, len) -- BMPString
  assert(id.pc == 0, "DER requires BMPString to be primitive, but it isn't")
  len = getNextEOC(s, len)
  return read(s, len)
end

function decode(s, kwargs)
  if type(s) == "string" then
    s = {[0]=s}
  end
  kwargs = kwargs or {}
  local id = decodeID(s)
  local len = decodeLen(s)
  -- print(s[0]:gsub(".",function(c)return("%02X"):format(c:byte())end))
  -- print(id.class, id.tag, id.pc, len)
  -- if kwargs.sametag and kwargs.sametag ~= id.tag then
  --   error(("Decoder for type 0x%s required the decoded tag to be the same, but it isn't"):format(kwargs.sametag))
  -- end
  if id.class == 0x02 and kwargs.context and kwargs.context[1] then
    id.tag = kwargs.context[1]
    table.remove(kwargs.context, 1)
  end
  local result = decoders[id.tag](s, id, len, kwargs)
  -- print(tostring(result):gsub(".",function(c)return("%02X"):format(c:byte())end))
  return result
end

return decode

-- An implementation of DER decoder.
-- It only implements the basic types.

local function read(s, len)
  local result = s[0]:sub(1, len)
  s[0] = s[0]:sub(len + 1, -1)
  return result
end

local function decodeID(s)
  local data = read(s, 1):byte()
  local tag = data & 0x1f
  data = data >> 4
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
  local data = read(s, 1)
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
    for i = 1, len, 1 do
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
  local firstByte = read(s, 1):byte()
  if len > 1 then
    local second8Bit = s[0]:sub(1, 1):byte()
    assert(not (firstByte == 0xff and second8Bit == 1 or firstByte == 0x00 and second8Bit == 0), "invalid value: first 9 bits are " .. second8Bit)
  end
  local result = 0
  if s[0]:sub(1, 1):byte() & 0x80 then
    result = -1
  end
  for i = 1, len, 1 do
    result = (result << 8) | read(s, 1):byte()
  end
  if result > (256^len)/2 then
    result = result - 256^len
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
    elseif firstByte = 0x41 then
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
    local result = 0
    for i = 1, #data, 1 do
      result = (result << 8) | data:sub(i, i):byte()
    end
    result = result >> rShift
    return result
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
    local data = read(s, len)
    local result = 0
    for i = 1, #data, 1 do
      result = (result << 8) | decode(s)
    end
    return result
  end
end

decoders[0x05] = function(s, id, len) -- NULL
  len = getNextEOC(s, len)
  assert(id.pc == 0, "NULL shall be primitive")
  assert(len == 0, "NULL must not have a content")
  return nil
end

decoders[0x10] = function(s, id, len) -- SEQUENCE & SEQUENCE OF
  assert(id.pc == 1, "SEQUENCE shall be constructed")
  local result = {}
  local lenleft = len
  while true do
    local prevlen = 0
    if len ~= "eoc" then
      prevlen = #s[0]
    end
    local decoded = decode(s)
    result[#result+1] = decoded
    if len ~= "eoc" then
      lenleft = lenleft - (prevlen - #s[0])
    end
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

decoders[0x11] = function(s, id, len) -- SET & SET OF
  assert(id.pc == 1, "SET shall be constructed")
  local result = {}
  local lenleft = len
  while true do
    local prevlen = 0
    if len ~= "eoc" then
      prevlen = #s[0]
    end
    local decoded = decode(s)
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
    result[#result] = (result[#result] << 7) | (byte & 0x7f)
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
  assert(id.pc == 0, "RELATIVE OBJECT IDENTIFIER shall be primitive")
  return decoders[0x06](s, id, len)
end

decoders[0x17] = function(s, id, len) -- UTCTime
  assert(id.pc == 0, "DER requires UTCTime to be primitive, bit it isn't")
  len = getNextEOC(s, len)
  local data = read(s, len)
  local year, month, day, hour, min, sec = data:match("^(%d%d%d%d)(%d%d)(%d%d)(%d%d)(%d%d)(%d%d)Z$")
  if not year then
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

return function decode(s, kwargs)
  local id = decodeID(s)
  local len = decodeLen(s)
  if kwargs.sametag and kwargs.sametag ~= id.tag then
    error(("Decoder for type 0x%s required the decoded tag to be the same, but it isn't"):format(kwargs.sametag))
  end
  return decoders[id.tag](s, id, len)
end

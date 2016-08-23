local com = require("component")
local unicode = require("unicode")

local inet = com.internet

local vcomponent = require("vcomponent")


-- UTILITIES -------------------------------------------------------------------

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

local function codec(encoder, decoder)
  return {
    encode = encoder,
    decode = decoder
  }
end

local function read(stream, len)
  local result = stream[0]:sub(1, len)
  stream[0] = stream[0]:sub(len + 1, -1)
  return result
end

local function unpack(stream, format)
  local result, len = format:unpack(stream[0])
  stream:read(len)
  return result
end

local function unpackBoolean(stream)
  local result = stream:read(1)
  return result == 0xff
end

-- Stream
local function s(str)
  return setmetatable(
    {
      [0] = str
    }, {
      __index = {
        read = read,
        unpack = unpack,
        unpackBoolean = unpackBoolean
      }
    }
  )
end

local function generatePalette(palette)
  -- Totally not stolen from ice player's code.
  -- Nope. Really.
  local result = palette or {}
  for i = 0, 239, 1 do
    local r = i % 6
    local g = (i // 6) % 8
    local b = (i // (6 * 8))
    r = (r * 255 + 2) // 5
    g = (g * 255 + 3) // 7
    b = (b * 255 + 2) // 4

    result[i + 16] = (r << 16) | (g << 8) | b
  end

  return enum(result)
end

-- what
local function colorDelta(c1, c2)
  local r1, g1, b1 = (c1 >> 16) & 0xff, (c1 >> 8) & 0xff, c1 & 0xff
  local r2, g2, b2 = (c2 >> 16) & 0xff, (c2 >> 8) & 0xff, c2 & 0xff
  local dr = r1 - r2
  local dg = g1 - g2
  local db = b1 - b2
  return .2126 * dr * dr + .7152 * dg * dg + .0722 * db * db
end

local function index2color(palette, i)
  if palette[i] then
    return palette[i]
  end
  i = i - 16
  local r = i % 6
  local g = (i // 6) % 8
  local b = (i // (6 * 8))
  r = (r * 255 + 2) // 5
  g = (g * 255 + 3) // 7
  b = (b * 255 + 2) // 4
  return (r << 16) | (g << 8) | b
end

local function color2index(palette, color)
  if palette[color] then
    return palette[color]
  end
  local r, g, b = (color >> 16) & 0xff, (color >> 8) & 0xff, color & 0xff
  local idxR = math.floor(r * 5 / 255 + .5)
  local idxG = math.floor(g * 7 / 255 + .5)
  local idxB = math.floor(b * 4 / 255 + .5)
  local idx = 16 + idxR * 8 * 5 + idxG * 5 + idxB
  local minDelta = math.huge
  local minDIdx = math.huge
  for i = 0, 15, 1 do
    local d = colorDelta(palette[i], color)
    if d < minDelta then
      minDelta = d
      minDIdx = i
    end
  end
  if delta(index2color(idx), color) < delta(index2color(minDIdx), color) then
    return idx
  else
    return minDIdx
  end
end


-- Opcodes (message types)
local opcodes = enum({
  Error = 00,           -- An error occured
  AuthClient = 01,      -- Authentication message sent by client to server
  AuthServer = 02,      -- Response to auth message
  InitialData = 03,     -- Initial set of parameters (bg, resolution, etc.)
  SetBG = 04,           -- setForeground()
  SetFG = 05,           -- setBackground()
  SetPalette = 06,      -- setPaletteColor()
  SetResolution = 07,   -- setResolution()
  SetChars = 08,        -- set()
  Copy = 09,            -- copy()
  Fill = 10,            -- fill()
  TurnOnOff = 11,       -- turnOn() / turnOff()
  SetPrecise = 12,      -- setPrecise()
  Fetch = 13,           -- Fetches data from the server (the same msg as InitialData)
  EventTouch = 14,      -- Touch event
  EventDrag = 15,       -- Drag event
  EventDrop = 16,       -- Drop event
  EventScroll = 17,     -- Scroll event
  EventKeyDown = 18,    -- Key pressed event
  EventKeyUp = 19,      -- Key released event
  EventClipboard = 20,  -- Clipboard paste event
  Ping = 21,            -- Ping
  Pong = 22             -- Pong
})

-- A set of pack formats
-- (the protocol is big-endian)
local uint8 = ">I1"
local uint16 = ">I2"
local uint24 = ">I3"
local uint32 = ">I4"
local uint64 = ">I4"

local str = ">s3"

local function packBoolean(bool)
  if bool then
    return uint8:pack(0xff)
  else
    return uint8:pack(0x00)
  end
end


-- PROTOCOL --------------------------------------------------------------------

local createRecord
do
  local function createPacket(self)
    return uint8:pack(self.opcode) .. str:pack(self.data)
  end
  function createRecord(opcode, data)
    return setmetatable({
      opcode = opcode,
      data = data
    }, {
      __index = {
        packet = createPacket
      }
    })
  end
end

-- Encoders & decoders
local codecs = {}

codecs[opcodes.Error] = codec(
  function(description)
    return s(str:pack(description))
  end,
  function(stream)
    return {
      description = stream:unpack(str)
    }
  end
)

codecs[opcodes.AuthClient] = codec(
  function(user, passwd, displayMode, pingInterval)
    return s(str:pack(user) .. str:pack(passwd) ..
             uint8:pack(displayMode) .. uint16:pack(pingInterval))
  end,
  function(stream)
    return {
      user = stream:unpack(str),
      password = stream:unpack(str),
      displayMode = stream:unpack(uint8),
      pingInterval = stream:unpack(uint16)
    }
  end
)

codecs[opcodes.AuthServer] = codec(
  function(authResult, displayMessage)
    return s(uint8:pack(authResult) .. str:pack(displayMessage))
  end,
  function(stream)
    return {
      authResult = stream:unpack(uint8),
      displayMessage = stream:unpack(str)
    }
  end
)

codecs[opcodes.InitialData] = codec(
  function(connectionMode, ...)
    if connectionMode == 01 then
      local palette, fg, bg, resolution, screenState, preciseMode, shownChars = ...
      local result = ""
      for i = 0, 15, 1 do
        result = result .. uint24:pack(palette[i])
      end
      result = result .. uint24:pack(color2index(palette, fg))
      result = result .. uint24:pack(color2index(palette, bg))
      result = result .. uint8:pack(resolution.w)
      result = result .. uint8:pack(resolution.h)
      result = result .. packBoolean(screenState)
      result = result .. packBoolean(preciseMode)
      result = result .. table.concat(shownChars)  -- list[w × h] = chars...
      return s(result)
    elseif connectionMode == 02 then
      return s("") -- no data
    else
      error("not implemented")
    end
  end,
  function(stream)
    local result = {}
    result.palette = {}
    for i = 0, 15, 1 do
      result.palette[i] = stream:unpack(uint24)
    end
    result.palette = generatePalette(result.palette)
    result.fg = index2color(result.palette, stream:unpack(uint8))
    result.bg = index2color(result.palette, stream:unpack(uint8))
    result.resolution = {}
    result.resolution.w = stream:unpack(uint8)
    result.resolution.h = stream:unpack(uint8)
    result.screenState = stream:unpackBoolean()
    result.preciseMode = stream:unpackBoolean()
    result.chars = {}
    for i = 1, result.h, 1 do
      result.chars[i] = {}
    end
    for i = 1, result.w * result.h, 1 do
      local x = i % w
      local y = i // w
      result.chars[y][x] = stream:read(1)
    end
    return result
  end
)

codecs[opcodes.SetBG] = codec(
  function(palette, color)
    return s(uint8:pack(color2index(palette, color)))
  end,
  function(stream)
    return {
      color = index2color(stream:unpack(uint8))
    }
  end
)

codecs[opcodes.SetFG] = codec(
  function(palette, color)
    return s(uint8:pack(color2index(palette, color)))
  end,
  function(stream)
    return {
      color = index2color(stream:unpack(uint8))
    }
  end
)

codecs[opcodes.SetPalette] = codec(
  function(index, color)
    return s(uint24:pack(color) .. uint8:pack(index))
  end,
  function(stream)
    return {
      color = stream:unpack(uint24),
      index = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.SetResolution] = codec(
  function(w, h)
    return s(uint8:pack(w) .. uint8:pack(h))
  end,
  function(stream)
    return {
      w = stream:unpack(uint8),
      h = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.SetChars] = codec(
  function(x, y, chars, vertical)
    local charStr = ""
    local i = 1
    while true do
      if #chars == 0 then
        break
      end
      local c = chars:sub(i, i)
      if unicode.isWide(c) then
        charStr = charStr .. c .. " "
        i = i + 2
      else
        charStr = charStr .. c
        i = i + 1
      end
    end
    return s(uint8:pack(x) .. uint8:pack(y) .. str:pack(charStr) .. packBoolean(vertical))
  end,
  function(stream)
    return {
      x = stream:unpack(uint8),
      y = stream:unpack(uint8),
      chars = stream:unpack(str),
      vertical = stream:unpackBoolean()
    }
  end
)

codecs[opcodes.Copy] = codec(
  function(x, y, w, h, tx, ty)
    tx = x + tx
    ty = y + ty
    return s(uint8:pack(x) .. uint8:pack(y) .. uint8:pack(w) ..
             uint8:pack(h) .. uint8:pack(tx) .. uint8:pack(ty))
  end,
  function(stream)
    return {
      x = stream:unpack(uint8),
      y = stream:unpack(uint8),
      w = stream:unpack(uint8),
      h = stream:unpack(uint8),
      tx = stream:unpack(uint8),
      ty = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.Fill] = codec(
  function(x, y, w, h, char)
    return s(uint8:pack(x) .. uint8:pack(y) .. uint8:pack(w) .. uint8:pack(h) .. char:sub(1, 1))
  end,
  function(stream)
    return {
      x = stream:unpack(uint8),
      y = stream:unpack(uint8),
      w = stream:unpack(uint8),
      h = stream:unpack(uint8),
      char = stream:read(1)
    }
  end
)

codecs[opcodes.TurnOnOff] = codec(
  function(on)
    return s(packBoolean(on))
  end,
  function(stream)
    return {
      on = stream:unpackBoolean()
    }
  end
)

codecs[opcodes.SetPrecise] = codec(
  function(precise)
    return s(packBoolean(percise))
  end,
  function(stream)
    return {
      precise = stream:unpackBoolean()
    }
  end
)

codecs[opcodes.Fetch] = codec(
  function()
    return s("")
  end,
  function(stream)
    return {}
  end
)

codecs[opcodes.EventTouch] = codec(
  function(x, y, button)
    return s(uint8:pack(x) .. uint8:pack(y) .. uint8:pack(button))
  end,
  function(stream)
    return {
      x = stream:unpack(uint8),
      y = stream:unpack(uint8),
      button = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.EventDrag] = codecs[opcodes.EevntTouch]
codecs[opcodes.EventDrop] = codecs[opcodes.EventTouch]

codecs[opcodes.EventScroll] = codec(
  function(x, y, direction)
    return s(uint8:pack(x) .. uint8:pack(y) .. uint8:pack(direction))
  end,
  function(stream)
    return {
      x = stream:unpack(uint8),
      y = stream:unpack(uint8),
      direction = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.EventKeyDown] = codec(
  function(char, code)
    return s(uint32:pack(utf8.codepoint(char)) .. uint32:pack(code))
  end,
  function(stream)
    return {
      char = utf8.char(stream:unpack(uint32)),
      code = stream:unpack(uint32)
    }
  end
)

codecs[opcodes.EventKeyUp] = codecs[opcodes.EventKeyDown]

codecs[opcodes.EventClipboard] = codec(
  function(data)
    return s(str:pack(data))
  end,
  function(stream)
    return {
      data = stream:unpack(str)
    }
  end
)

codecs[opcodes.Ping] = codec(
  function(rndNum)
    return s(uint64:pack(rndNum))
  end,
  function(stream)
    return {
      ping = stream:unpack(uint64)
    }
  end
)

codecs[opcodes.Pong] = codec(
  function(rndNum)
    return s(uint64:pack(rndNum))
  end,
  function(stream)
    return {
      pong = stream:unpack(uint64)
    }
  end
)

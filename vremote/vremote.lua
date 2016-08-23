local com = require("component")
local unicode = require("unicode")

local inet = com.internet

local vcomponent = require("vcomponent")


-- When true, the program will be wrapped in pcall
-- to avoid double-registering components.
local safeMode = false

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

  return result
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
  local _, pos = isin(palette, color)
  if pos then
    return pos
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
local ustr = ">s1"

local function packBoolean(bool)
  if bool then
    return uint8:pack(0xff)
  else
    return uint8:pack(0x00)
  end
end


-- PROTOCOL --------------------------------------------------------------------

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
    if connectionMode == 00 or connectionMode == 01 then
      local palette, fg, bg, resolution, screenState, preciseMode, shownChars = ...
      local result = ""
      for i = 0, 15, 1 do
        result = result .. uint24:pack(palette[i])
      end
      result = result .. uint8:pack(fg)
      result = result .. uint8:pack(bg)
      result = result .. uint8:pack(resolution.w)
      result = result .. uint8:pack(resolution.h)
      result = result .. packBoolean(screenState)
      result = result .. packBoolean(preciseMode)
      for i = 1, #shownChars, 1 do
        for j = 1, #shownChars[i], 1 do
          result = result .. ustr:pack(shownChars[3 * (j * resolution.w + i)]) ..
                   uint8:pack(shownChars[3 * (j * resolution.w + i) + 1]) ..
                   uint8:pack(shownChars[3 * (j * resolution.w + i) + 2])
        end
      end
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
    result.fg = stream:unpack(uint8)
    result.bg = stream:unpack(uint8)
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
      local x = i % resolution.w
      local y = i // resolution.w
      result.chars[3 * (y * result.resolution.w + x)] = stream:unpack(ustr)
      result.chars[3 * (y * result.resolution.w + x) + 1] = stream:unpack(uint8)
      result.chars[3 * (y * result.resolution.w + x) + 2] = stream:unpack(uint8)
    end
    return result
  end
)

codecs[opcodes.SetBG] = codec(
  function(color)
    return s(uint8:pack(color))
  end,
  function(stream)
    return {
      color = stream:unpack(uint8)
    }
  end
)

codecs[opcodes.SetFG] = codec(
  function(color)
    return s(uint8:pack(color))
  end,
  function(stream)
    return {
      color = stream:unpack(uint8)
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


-- Packets
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

local function parseRecord(stream)
  local opcode = stream:unpack(uint8)
  local length = stream:unpack(uint24)
  local data = stream:read(length)
  if #data ~= length then
    error("corrupt packet: incorrect length")
  end
  if not opcodes[opcode] then
    error("corrupt packet: unknown opcode")
  end
  return createRecord(opcode, data)
end

local function readRecords(stream)
  local result = {}
  while #stream > 0 do
    local record = parseRecord(stream)
    result[#result + 1] = record
  end
  return result
end


-- VIRTUAL COMPONENTS ----------------------------------------------------------

local function registerVirtualComponents(write)
  local gpuAddr = vcomponent.uuid()
  local screenAddr = vcomponent.uuid()
  local kbdAddr = vcomponent.uuid()

  local params = {
    palette = {},
    fg = 0,
    bg = 0,
    resolution = {
      w = 160,
      h = 50
    },
    screenState = true,
    preciseMode = false,
    chars = {}
  }

  local function char(x, y, i, val)
    i = i or 0
    if not val then
      return params.chars[3 * (y * params.resolution.w + x) + i]
    end
    params.chars[3 * (y + params.resolution.w + x) + i] = val
  end

  -- Initialize and generate the palette
  for i = 0, 15, 1 do
    local shade = 0xff * (i + 1) / 17
    params.palette[i] = (shade << 16) | (shade << 8) | shade
  end
  params.palette = generatePalette(palette)
  for i = 0, 255, 1 do
    if palette[i] == 0xffffff then
      params.fg = i
    end
    if palette[i] == 0x000000 then
      params.bg = i
    end
  end

  -- Initialize the screen to blank characters
  for i = 0, params.resolution.w * params.resolution.h * 3 - 1, 3 do
    params.chars[i+0] = " "
    params.chars[i+1] = params.fg
    params.chars[i+2] = params.bg
  end

  -- GPU proxy
  local gpu = {}
  gpu.bind = function()
    return false
  end
  gpu.getScreen = function()
    return screenAddr
  end
  gpu.getBackground = function()
    return index2color(params.bg), params.bg < 16
  end,
  gpu.setBackground = function(color, palIdx)
    checkArg(1, color, "number")
    checkArg(2, palIdx, "boolean", "nil")
    local shouldSend = false
    if palIdx then
      if color < 0 or color > 15 then
        error("invalid palette index")
      end
      if params.bg ~= color then
        params.bg = color
        shouldSend = true
      end
    else
      color = color2index(params.palette, color)
      if color ~= params.bg then
        params.bg = color
        shouldSend = true
      end
    end
    if shouldSend then
      local data = codecs[opcodes.SetBG].encode(color)
      local record = createRecord(opcodes.SetBG, data)
      write(createRecord(opcodes.SetBG, codecs[opcodes.SetBG].encode(color)):packet())
    end
    return true
  end
  gpu.getForeground = function()
    return index2color(params.fg), params.fg < 16
  end
  gpu.setForeground = function(color, palIdx)
    checkArg(1, color, "number")
    checkArg(2, palIdx, "boolean", "nil")
    local shouldSend = false
    if palIdx then
      if color < 0 or color > 15 then
        error("invalid palette index")
      end
      if params.fg ~= color then
        params.fg = color
        shouldSend = true
      end
    else
      local color = color2index(params.palette, color)
      if params.fg ~= coloe then
        params.fg = color
        shouldSend = true
      end
    end
    if shouldSend then
      write(createRecord(opcodes.SetFG, codecs[opcodes.SetFG].encode(color)):packet())
    end
    return true
  end
  gpu.getPaletteColor = function(index)
    checkArg(1, index, "number")
    if index < 0 or index > 15 then
      error("invalid palette index")
    end
    return params.palette[index]
  end
  gpu.setPaletteColor = function(index, color)
    checkArg(1, index, "number")
    checkArg(2, color, "number")
    color = color & 0xffffff
    if index < 0 or index > 15 then
      error("invalid palette index")
    end
    if params.palette[index] ~= color then
      params.palette[index] = color
      write(createRecord(opcodes.SetPalette, codecs[opcodes.SetPalette].encode(index, color)):packet())
    end
    return true
  end
  gpu.maxDepth = function()
    return 8
  end
  gpu.getDepth = function()
    return 8
  end
  gpu.setDepth = function()
    return false
  end
  gpu.maxResolution = function()
    return 160, 50
  end
  gpu.setResolution = function(w, h)
    checkArg(1, w, "number")
    checkArg(2, h, "number")
    if h < 1 or w < 1 or h > 50 or w > 160 then
      error("unsupported resolution")
    end
    if params.resolution.w ~= w or params.resolution.h ~= h then
      params.resolution.w, params.resolution.h = w, h
      write(createRecord(opcodes.SetResolution, codecs[opcodes.SetResolution].encode(w, h)):packet())
    end
    return true
  end
  gpu.getResolution = function()
    return params.resolution.w, params.resolution.h
  end
  gpu.get = function(x, y)
    checkArg(x, "number")
    checkArg(y, "number")
    if x < 1 or x > params.resolution.w or y < 1 or y > params.resolution.h then
      error("index out of bounds")
    end
    local result = {
      char(x, y), char(x, y, 1), char(x, y, 2)
    }
    result[4] = result[2] < 16 and result[2] or nil
    result[5] = result[3] < 16 and result[3] or nil
    result[2] = index2color(params.palette, result[2])
    result[3] = index2color(params.palette, result[3])
    return table.unpack(result)
  end
  gpu.set = function(x, y, chars, vertical)
    checkArg(x, "number")
    checkArg(y, "number")
    checkArg(chars, "string")
    checkArg(vertical, "boolean", "nil")
    -- it makes no sense to send characters that are out of screen's bounds
    if vertical then
      chars = unicode.sub(chars, 1, params.resolution.h - y + 1)
    else
      chars = unicode.sub(chars, 1, params.resolution.w - x + 1)
    end
    -- Handle wide characters
    local nChars = ""
    for i = 1, unicode.len(chars), 1 do
      local c = unicode.sub(chars, i, i)
      nChars = nChars .. c
      if unicode.isWide(c) then
        nChars = nChars .. " "
      end
    end
    -- Recheck again
    if vertical then
      chars = unicode.sub(chars, 1, params.resolution.h - y + 1)
    else
      chars = unicode.sub(chars, 1, params.resolution.w - x + 1)
    end
    -- check if we really need to update something
    -- (we could also update only the chars that needs to be updated...
    -- but, y'know, it's overkill IMO)
    local needsUpdate = false
    for i = 0, unicode.len(chars) - 1, 1 do
      local ix, iy = x, y
      if vertical then
        iy = iy + i
      else
        ix = ix + i
      end
      if unicode.sub(chars, i, i) ~= char(ix, ij) or
          char(ix, ij, 1) ~= params.fg or
          char(ix, ij, 2) ~= params.bg then
        needsUpdate = true
        break
      end
    end
    if needsUpdate then
      for i = 0, unicode.len(chars) - 1, 1 do
        local c = unicode.sub(chars, i, i)
        local ix, iy = x, y
        if vertical then
          iy = iy + i
        else
          ix = ix + i
        end
        char(ix, ij, 0, c)
        char(ix, iy, 1, params.fg)
        char(ix, ij, 2, params.bg)
      end
      write(createRecord(opcodes.SetChars, codecs[opcodes.SetChars].encode(x, y, chars, vertical)):packet())
    end
    return true
  end
  gpu.copy = function(x, y, w, h, tx, ty)
    checkArg(1, x, "number")
    checkArg(2, y, "number")
    checkArg(3, w, "number")
    checkArg(4, h, "number")
    checkArg(5, tx, "number")
    checkArg(6, ty, "number")
    if x < 1 or y < 1 or x > params.resolution.w or y > params.resolution.h then
      error("index out of bounds")
    end
    w = math.max(w, 0)
    h = math.max(h, 0)
    if w == 0 or h == 0 then
      -- pass
      return true
    end
    if w > params.resolution.w - x + 1 then
      w = params.resolution.w - x + 1
    end
    if h > params.resolution.h - y + 1 then
      h = params.resolution.h - y + 1
    end
    if (tx > params.resolution.w - x or x + w + tx - 1 < 1) and
        (ty > params.resolution.h - y or y + h + ty - 1 < 1) then
      -- pass
      return true
    end
    -- region that's copied
    local region = {}
    for j = y, y + h - 1, 1 do
      for i = x, x + w - 1, 1 do
        -- copy cells
        region[3 * (j * params.resolution.w + i)] = char(i, j)
        region[3 * (j * params.resolution.w + i) + 1] = char(i, j, 1)
        region[3 * (j * params.resolution.w + i) + 2] = char(i, j, 2)
      end
    end
    for j = y, y + h - 1, 1 do
      for i = x, x + w - 1, 1 do
        local ix = i + tx
        local iy = j + ty
        char(ix, ij, 0, region[3 * (j * params.resolution.w + i)])
        char(ix, ij, 1, region[3 + (j + params.resolution.w + i) + 1])
        char(ix, ij, 2, region[3 + (j + params.resolution.w + i) + 2])
      end
    end
    write(createRecord(opcodes.Copy, codecs[opcodes.Copy].encode(x, y, w, h, tx, ty)):packet())
  end
  gpu.fill = function(x, y, w, h, char)
    checkArg(1, x, "number")
    checkArg(2, y, "number")
    checkArg(3, w, "number")
    checkArg(4, h, "number")
    checkArg(5, char, "string")
    if x < 1 or x > params.resolution.w or y < 1 or y > params.resolution.h then
      error("index out of bounds")
    end
    w = math.max(w, 0)
    h = math.max(h, 0)
    char = unicode.sub(char, 1, 1)
    checkArg(5, char, "string")
    local shouldSend = false
    for j = y, y + h - 1, 1, do
      for i = x, x + w - 1, 1 do
        if char(i, j) ~= char then
          shouldSend = true
          char(i, j, 0, char)
          char(i, j, 1, params.fg)
          char(i, j, 2, params.bg)
        end
      end
    end
    if shouldSend then
      write(createRecord(opcodes.Fill, codecs[opcodes.Fill].encode(x, y, w, h, char)):packet())
    end
  end

  -- Screen proxy
  local screen = {}
  screen.isOn = function()
    return params.screenState
  end
  screen.turnOn = function()
    local shouldSend = params.screenState ~= true
    params.screenState = true
    if shouldSend then
      write(createRecord(opcodes.TurnOnOff, codecs[opcodes.TurnOnOff].encode(true)):packet())
    end
    return shouldSend
  end
  screen.turnOff = function()
    local shouldSend = params.screenState ~= false
    params.screenState = false
    if shouldSend then
      write(createRecord(opcodes.TurnOnOff, codecs[opcodes.TurnOnOff].encode(false)):packet())
    end
    return shouldSend
  end
  screen.getAspectRatio = function()
    return 1, 1
  end
  screen.getKeyboards = function()
    return {kbdAddr}
  end
  screen.setPrecise = function(precise)
    checkArg(1, precise, "boolean")
    local shouldSend = params.screenState ~= precise
    params.screenState = precise
    if shouldSend then
      write(createRecord(opcodes.SetPrecise, codecs[opcodes.SetPrecise].encode(precise)):packet())
    end
    return true
  end
  screen.isPrecise = function()
    return params.screenState
  end
  screen.setTouchModeInverted = function()
    return false
  end
  screen.isTouchModeInverted = function()
    return false
  end

  -- Register vcomponents, turn safe mode on
  safeMode = true
  vcomponent.register(gpuAddr, "gpu", gpu)
  vcomponent.register(screenAddr, "screen", screen)
  vcomponent.register(kbdAddr, "keyboard", {})

  return params, gpuAddr, screenAddr, kbdAddr
end

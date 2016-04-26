local comp = require("computer")
local event = require("event")

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function getType(v)
  local t = type(v)
  if t == "table" then
    t = v.__name or (getmetatable(v) or {}).__name or t
  end
  return t
end

local function checkType(name, value, ...)
  local types = {...}
  for _, t in pairs(types) do
    if getType(value) == t then
      return true
    end
  end
  local exp = ""
  if #types == 0 then
    return true
  elseif #types == 1 then
    exp = types[1]
  elseif #types == 2 then
    exp = table.concat(types, ", ")
  elseif #types > 2 then
    exp = table.concat(types, ", ", 1, #types - 1) .. ", or " .. types[#types]
  end
  error(("bad argument %s (%s expected, got %s)"):format(tonumber(name) and ("#" .. name) or ('"' .. name .. '"'), exp, getType(value)))
end


--  Chord
--    Stores an array of frequency-length tables.

local Chord = {}
Chord.__name = "Chord"

function Chord:new()
  local o = {data={}}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Chord:add(...)
  local tbl = {...}
  for num, item in ipairs(tbl) do
    item[1] = tonumber(item.freq or item.f or item[1])
    item[2] = tonumber(item.length or item.l or item[2])
    item[3] = tonumber(item.instrument or item.instr or item[3])
    item[4] = tonumber(item.volume or item.vol or item.v or item[4]) or 1
    item.f = nil
    item.freq = nil
    item.l = nil
    item.length = nil
    item.instrument = nil
    item.instr = nil
    item.vol = nil
    item.v = nil
    item.volume = nil
    if not tonumber(item[1]) or not tonumber(item[2]) or not tonumber(item[3]) then
      error("bad table " .. (item.__name or "#" .. num) .. ": expected {number, number, number}, got {" .. type(item[1]) .. ", " .. type(item[2]) .. ", " .. type(item[3]) .. "}")
    end
    table.insert(self.data, item)
  end
  return true
end

function Chord:get()
  return self.data
end

function Chord:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    if self.data[pos] then
      return table.unpack(self.data[pos])
    else
      return nil
    end
  end
end

Chord.__ipairs = Chord.__pairs



--  Buffer
--    Stores an array of Chords, and its length.
--    Calls a given function when reaches a specific time.

local Buffer = {}
Buffer.__name = "Buffer"

function Buffer:new(args)
  checkType(1, args, "table")
  local func = args.func
  local to = args.timeout or args.to
  checkType("func", func, "function")
  checkType("to", to, "number")
  local o = {data={},length=0,func=func,to=to,pos=1,called=false}
  o = setmetatable(o, self)
  self.__index = self
  return o
end

function Buffer:seek(pos)
  checkType(1, pos, "number")
  if pos > self.length then
    self.pos = self.length
  elseif pos < 1 then
    self.pos = 1
  else
    self.pos = pos
  end
end

function Buffer:add(...)
  local args = {...}
  if #args == 0 then
    return
  end
  for num, item in ipairs(args) do
    local tick = item.tick or item.t or item[1]
    local chord = item.chord or item.c or item[2]
    checkType(num, tick, "number")
    checkType(num, chord, "Chord")
    table.insert(self.data, {tick, chord})
    self.length = math.max(self.length, tick)
  end
  return true
end

function Buffer:getLength()
  for _, item in pairs(self.data) do
    self.length = math.max(self.length, item[1])
  end
  return self.length
end

function Buffer:play()
  local chords = {}
  for k, v in ipairs(self.data) do
    if v[1] == self.pos then
      table.insert(chords, v[2])
    end
  end
  if self.pos == self:getLength() - self.to + 1 and not self.called then
    -- Run a new buffer generator function
    self:func()
    self.called = true
  end
  self.pos = self.pos + 1
  if self.pos - 1 <= self.length then
    return chords
  else
    return nil
  end
end

function Buffer:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    if self.data[pos] then
      return table.unpack(self.data[pos])
    else
      return nil
    end
  end
end

function Buffer:__ipairs()
  local grouped = {}
  for k, v in pairs(self.data) do
    grouped[v[1]] = grouped[v[1]] or {}
    table.insert(grouped[v[1]], v[2])
  end
  local pos = -1
  return function()
    pos = pos + 1
    return pairs(grouped)
  end
end



--  Track
--    Stores buffers and audio info.

local Track = {}
Track.__name = "Track"

function Track:new(args)
  checkType(1, args, "table")
  local tempo = args.tempo
  checkType("tempo", tempo, "number")
  local o = {data={},tempo=tempo,length=0,pos=1}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Track:getLength()
  self.length = 0
  for _, b in pairs(self.data) do
    self.length = b:getLength()
  end
  return self.length
end

function Track:add(buffer)
  checkType(1, buffer, "Buffer")
  table.insert(self.data, buffer)
  self:getLength()
  return #self.data
end

function Track:seek(pos)
  if not self.data[pos] then
    self.pos = self.length
  elseif pos < 1 then
    self.pos = 1
  else
    self.pos = pos
  end
  if self.data[pos] then
    self.data[pos]:seek(1)
  end
end

function Track:play()
  self:getLength()
  if not self.data[self.pos] then
    return false, "end"
  end
  local result = self.data[self.pos]:play()
  if result == nil then
    self.pos = self.pos + 1
    if self.data[self.pos] then
      self.data[self.pos]:seek(1)
    end
    return self:play()
  end
  return result
end

function Track:__pairs()
  local pos = -1
  return function()
    pos = pos + 1
    return self.data[pos]
  end
end

Track.__ipairs = Track.__pairs



--  Music
--    A handle, connects Track and devices.

local Music = {}
Music.__name = "Music"

function Music:new(track, onCloseImpl)
  checkType(1, track, "Track")
  onCloseImpl = onCloseImpl or function() end
  checkType(2, onCloseImpl, "function")
  local o = {track = track, devices = {}, timer = false, stopped = false, onClose = onCloseImpl}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Music:connect(device)
  checkType(1, device, "Device")
  table.insert(self.devices, device)
end

function Music:disconnect(device)
  checkType(1, device, "Device")
  local _, pos = isin(self.devices, device)
  if not pos then
    error("no such device")
  end
  table.remove(self.devices, pos)
end

function Music:seek(pos)
  self.track:seek(pos)
end

function Music:play(len, allowSleeping)
  checkType(1, len, "number")
  local lastSleep = comp.uptime()
  for i = 1, len, 1 do
    if self.stopped then
      return false, "stopped"
    end
    local success, reason = self.track:play()
    if not success then
      return success, reason
    end
    for _, dev in pairs(self.devices) do
      dev:play(success)
    end
    if allowSleeping and 1 / self.track.tempo * 100 % 5 == 0 then
      os.sleep(1 / self.track.tempo)
      lastSleep = comp.uptime()
    else
      local begin = comp.uptime()
      while comp.uptime() - begin < 1 / self.track.tempo do
        if comp.uptime() - lastSleep > 2.5 then
          os.sleep(.05)
          lastSleep = comp.uptime()
        end
      end
    end
  end
  return true
end

function Music:getPos()
  return self.track.pos
end

function Music:getLength()
  return self.track:getLength()
end


-- After a bit of thinking, I decided to remove these two methods completely
-- and make programs to handle all of the BG-playing stuff by themselves.
-- Because I don't want neither to copy-paste the code just to change a delay handling,
-- nor to create some additional params for the :play() method.
-- So, rest in peace.
--[[
function Music:bgPlayStart(len)
  checkType(1, len, "number")
  if self.timer then
    return false, "already playing in background"
  end
  local timer, reason = event.timer(0, function()
    local success, reason = self:play(len, true)
    if not success then
      self:bgPlayStop()
    end
  end, 1)
  self.timer = timer
end

function Music:bgPlayStop()
  if not self.timer then
    return
  end
  event.cancel(self.timer)
  self.timer = false
end
]]--

function Music:close()
  self:onClose()
  self.stopped = true
  self.track = nil
end



--  Device
--    Class used by Music to play Chords

local Device = {}
Device.__name = "Device"

function Device:new(playImpl)
  checkType(1, playImpl, "function")
  local o = {play = playImpl}
  setmetatable(o, self)
  self.__index = self
  return o
end



--  Instruments

local instr = {
  piano = 1,
  drum = 2,
  snare = 3,
  click = 4,
  bass = 5
}



local function callable(class) -- Sugar! Makes a class callable.
  class.__name = class.__name or "<?>"
  class.__tostring = function()
    return "Object \"" .. class.__name .. "\""
  end
  return setmetatable(class, {
    __call = class.new,
    __tostring = function()
      return "Class \"" .. class.__name .. "\""
    end,
    __name = class
  })
end

return {
  Chord = callable(Chord),
  Buffer = callable(Buffer),
  Track = callable(Track),
  Music = callable(Music),
  Device = callable(Device),
  instr = instr
}

-- vim: expandtab tabstop=2 shiftwidth=2 :

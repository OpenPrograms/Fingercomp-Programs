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
  error(("bad argument %s (%s expected, got %s)"):format(tonumber(name) and ("#" .. name) or ('"' .. name .. '"'), exp, getType(value)), 2)
end



local formatTypes = {
  "NOTE",
  "WAVE",
  "BOTH",
  NOTE = 1,
  WAVE = 2,
  BOTH = 3
}


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

function Chord:add(freq, length, instr, volume)
  checkType(1, freq, "number")
  checkType(2, length, "number")
  checkType(3, instr, "number")
  checkType(4, volume, "number")
  self.data[#self.data+1] = {freq, length, instr, volume}
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
  local o = {data={},tempo=tempo,length=0,pos=1,info={}}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Track:getLength()
  self.length = 0
  for _, b in pairs(self.data) do
    self.length = self.length + b:getLength()
  end
  return self.length
end

function Track:getPos()
  local result = 0
  for i = 1, self.pos - 1, 1 do
    if self.data[i] then
      result = result + self.data[i]:getLength()
    end
  end
  if self.data[self.pos] then
    result = result + self.data[self.pos].pos
  end
  return result
end

function Track:add(buffer)
  checkType(1, buffer, "Buffer")
  table.insert(self.data, buffer)
  self:getLength()
  return #self.data
end

function Track:setInfo(info)
  checkType(1, info, "table")
  self.info = info
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

function Track:get()
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
    return self:get()
  end
  return result
end

function Track:play(len, sleepMode)
  checkType(1, len, "number")
  if sleepMode == 1 or sleepMode == "allow" or sleepMode == true then
    sleepMode = "allow"
  elseif sleepMode == 2 or sleepMode == "force" then
    sleepMode = "force"
  elseif sleepMode == -1 or sleepMode == "forbid" then
    sleepMode = "deny"
  else
    sleepMode = "none"
  end
  local lastSleep = os.clock()
  local lastTick = 0
  for i = 1, len, 1 do
    if self.closed then
      return false, "close"
    end
    if self.stopped then
      return false, "stopped"
    end
    local success, reason = self:get()
    if not success then
      return success, reason
    end
    if not (#success == 0 and (i - lastTick) / self.tempo > .1) then
      coroutine.yield(success)
      local sleepTime = (i - lastTick) / self.tempo
      lastTick = i
      if sleepMode == "force" and sleepTime < .05 then
        return false, "too fast"
      end
      if sleepMode == "allow" and sleepTime * 100 % 5 == 0 or sleepMode == "force" then
        os.sleep(sleepTime)
        lastSleep = os.clock()
      else
        if sleepTime >= .1 and sleepMode ~= "deny" then
          local sleep = math.floor(sleepTime * 100) == sleepTime * 100 and sleepTime - 0.05 or math.floor(sleepTime * 100) / 100
          os.sleep(sleep)
          sleepTime = sleepTime - sleep
          lastSleep = os.clock()
        end
        local begin = os.clock()
        while os.clock() - begin < sleepTime do
          if os.clock() - lastSleep > 2.5 then
            os.sleep(.05)
            lastSleep = os.clock()
            begin = begin + 0.05
          end
        end
      end
    end
  end
  return true
end

function Track:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    return self.data[pos]
  end
end

Track.__ipairs = Track.__pairs



--  Instruction
--    Stores an instruction

local Instruction = {}
Instruction.__name = "Instruction"

function Instruction:new(name, ...)
  checkType(1, name, "string")
  local o = {name=name, ...}
  setmetatable(o, self)
  self.__index = self
  return o
end



--  WaveBuffer
--    An instructions container

local WaveBuffer = {}
WaveBuffer.__name = "WaveBuffer"

function WaveBuffer:new(length, func, to)
  checkType(1, length, "number", "nil")
  checkType(2, func, "function", "nil")
  checkType(3, to, "number", "nil")
  length = length or math.huge
  to = to or 0
  local o = {length=length,pos=0,func=func,called=called,to=to}
  setmetatable(o, self)
  self.__index = self
  return o
end

function WaveBuffer:add(instruction)
  checkType(1, instruction, "Instruction")
  self[#self + 1] = instruction
end

function WaveBuffer:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    return self[pos]
  end
end

function WaveBuffer:getLength()
  return self.length
end

function WaveBuffer:play()
  if self.func and self.pos == self:getLength() - self.to + 1 and not self.called then
    self:func()
    self.called = true
  end
  self.pos = self.pos + 1
  return self[self.pos]
end

-- TODO: newPos should be some time moment, not instruction pos
function WaveBuffer:seek(newPos)
  if newPos > self:getLength() then
    self.pos = self.length
  elseif newPos < 1 then
    self.pos = 1
  else
    self.pos = newPos
  end
end

function WaveBuffer:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    return self[pos]
  end
end

WaveBuffer.__ipairs = WaveBuffer.__pairs



--  WaveTrack
--    Provides functions for the Music class

local WaveTrack = {}
WaveTrack.__name = "WaveTrack"

function WaveTrack:new()
  local o = {data={},pos=1,length=math.huge,info={}}
  setmetatable(o, self)
  self.__index = self
  return self
end

function WaveTrack:add(buf)
  checkType(1, buf, "WaveBuffer")
  table.insert(self.data, buf)
end

function WaveTrack:get()
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
    return self:get()
  end
  return result
end

function WaveTrack:getLength()
  self.length = 0
  for _, buf in pairs(self.data) do
    self.length = self.length + buf:getLength()
  end
  return self.length
end

function WaveTrack:getPos()
  return self.pos
end

function WaveTrack:play(length)
  checkType(1, length, "number")
  for i = 1, length, 1 do
    local success, reason = self:get()
    if not success then
      return success, reason
    end
    coroutine.yield(success)
  end
end

function WaveTrack:seek(newPos)
  if newPos > self:getLength() then
    newPos = self.length
  elseif newPos < 1 then
    newPos = 1
  end
  for _, buf in pairs(self.data) do
    if buf:getLength() >= newPos then
      buf:seek(newPos)
    end
    newPos = newPos - buf:getLength()
  end
end

function WaveTrack:setInfo(info)
  checkType(1, info, "table")
  self.info = info
end

function WaveTrack:__pairs()
  local pos = 0
  return function()
    pos = pos + 1
    return self.data[pos]
  end
end

WaveTrack.__ipairs = WaveTrack.__pairs



--  Music
--    A handle, connects Track (or WaveTrack) and devices.

local Music = {}
Music.__name = "Music"

function Music:new(track, onCloseImpl)
  checkType(1, track, "Track", "WaveTrack")
  onCloseImpl = onCloseImpl or function() end
  checkType(2, onCloseImpl, "function")
  local o = {track = track, devices = {}, timer = false, stopped = false, onClose = onCloseImpl, trackType = track.__name == "Track" and formatTypes.NOTE or formatTypes.WAVE}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Music:connect(device)
  checkType(1, device, "Device")
  assert(device.format == formatTypes.BOTH or device.format == self.trackType, "device doesn't support track's format")
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

function Music:play(...)
  local c = coroutine.create(self.track.play)
  local args = {self.track, ...}
  while true do
    local data = {coroutine.resume(c, table.unpack(args))}
    if #args > 0 then
      for i = #args, 1, -1 do
        table.remove(args, i)
      end
    end
    if data[1] == false then
      -- Something wrong happened, panic
      error(data[2], 2)
    end
    if coroutine.status(c) == "dead" then
      -- Return, the coroutine is now dead
      return table.unpack(data, 2)
    end
    for _, dev in pairs(self.devices) do
      dev:play(table.unpack(data, 2))
    end
  end
end

function Music:getPos()
  return self.track:getPos()
end

function Music:getLength()
  return self.track:getLength()
end

function Music:stop()
  self.stopped = true
end

function Music:close()
  self:onClose()
  self.closed = true
  self.track = nil
end



--  Device
--    A class used to generate sounds

local Device = {}
Device.__name = "Device"

function Device:new(playImpl, format, onVolumeChange)
  checkType(1, playImpl, "function")
  assert(formatTypes[format], "wrong format type!")
  checkType(3, onVolumeChange, "function", "nil")
  local o = {play = playImpl,volume=1,format=format,onVolumeChange=onVolumeChange}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Device:setVolume(vol)
  checkType(1, vol, "number")
  if vol < 0 or vol > 1 then
    error("Wrong volume: a value [0, 1] expected")
  end
  self.volume = vol
  if self.onVolumeChange then
    self.onVolumeChange()
  end
end



--  Instruments

local instr = {
  "piano",
  "drum",
  "snare",
  "click",
  "bass",
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
  [formatTypes.NOTE] = {
    Chord = callable(Chord),
    Buffer = callable(Buffer),
    Track = callable(Track),
    Music = callable(Music),
    instr = instr
  },
  [formatTypes.WAVE] = {
    WaveBuffer = callable(WaveBuffer),
    Instruction = callable(Instruction),
    WaveTrack = callable(WaveTrack)
  },
  Device = callable(Device),
  Music = callable(Music),
  formatTypes = formatTypes
}

-- vim: expandtab tabstop=2 shiftwidth=2 :

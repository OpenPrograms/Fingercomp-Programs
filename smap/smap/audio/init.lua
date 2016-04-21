local event = require("event")

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
    item.freq = item.freq or item.f or item[1]
    item.length = item.length or item.l or item[2]
    item.instr = item.instrument or item.instr or item[3]
    item.f = nil
    item[1] = nil
    item.l = nil
    item[2] = nil
    item.instrument = nil
    item[3] = nil
    if not tonumber(item.freq) or not tonumber(item.length) then
      error("bad table " .. (item.__name or "#" .. num) .. ": expected {number, number, string}, got {" .. type(item.freq) .. ", " .. type(item.length) .. ", " .. type(item.instr) .. "}")
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
      return self.data[pos].freq, self.data[pos].length, self.data[pos].instr
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
  self.func, self.to = func, to
  local o = {data={},length=0,func=nil,to=math.huge,pos=1,called=false}
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
    table.insert(self.data, {tick = tick, chord = chord})
    self.length = math.max(self.length, tick)
  end
  return true
end

function Buffer:getLength()
  for _, item in pairs(self.data) do
    self.length = math.max(self.length, item.tick)
  end
  return self.length
end

function Buffer:play()
  local chords = {}
  for k, v in ipairs(self.data) do
    if v.tick == self.pos then
      table.insert(chords, v.chord)
    end
  end
  if self.pos == self.to and not self.called then
    -- Run a new buffer generator function
    self.func(self)
    self.called = false
  end
  self.pos = self.pos + 1
  if self.pos <= self.length then
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
      return self.data[pos].tick, self.data[pos].chord
    else
      return nil
    end
  end
end

function Buffer:__ipairs()
  local grouped = {}
  for k, v in pairs(self.data) do
    grouped[v.tick] = grouped[v.tick] or {}
    table.insert(grouped[v.tick], v.chord)
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
  self.tempo = tempo
  local o = {data={},tempo=0,length=0,pos=1}
  setmetatable(o, self)
  self.__index = self
  return o
end

function Track:getLength()
  if #self.data > 0 then
    self.length = self.data[#self.data]:getLength()
  else
    self.length = 0
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

function Music:new(track)
  checkType(1, track, "Track")
  local o = {track = track, devices = {}, timer = nil, stopping = false}
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

function Music:play(len)
  checkType(1, len, "number")
  if self.timer then
    return false, "already playing in background"
  end
  for i = 1, len, 1 do
    if self.stopping then
      return false, "stopped"
    end
    local success, reason = self.track:play()
    if not success then
      return success, reason
    end
    for _, dev in pairs(self.devices) do
      dev:play(success)
    end
    os.sleep(1 / self.track.tempo)
  end
  return true
end

function Music:getPos()
  return self.track.pos
end

function Music:getLength()
  return self.track:getLength()
end

function Music:bgPlayStart(len)
  if self.timer then
    return false, "already plaring in background"
  end
  self.timer = event.timer(1 / self.timer.tempo, function()
    local success = self:play(1)
    if not success then
      self:bgPlayStop()
    end
  end, len)
end

function Music:bgPlayStop()
  if not self.timer then
    return
  end
  event.cancel(self.timer)
  self.timer = nil
end

function Music:stop()
  self:bgPlayStop()
  self.stopping = true
end

function Music:resume()
  self.stopping = false
end



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
  Music = callable(Music)
}

-- vim: expandtab tabstop=2 shiftwidth=2 :

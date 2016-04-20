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
  error(("bad argument %s (%s expected, got %s)"):format(tonumber(name) and ("#" .. name) or ('"' .. name .. '"'), getType(value)))
end


--  Chord
--    Stores an array of frequency-length tables.

local Chord = {data={}}
Chord.__name = "Chord"

function Chord:new()
  local o = setmetatable({}, self)
  self.__index = self
  return o
end

function Chord:add(flt, ...)
  local tbl = {flt, ...}
  for num, item in ipairs(tbl) do
    item.freq = item.freq or item.f or item[1]
    item.length = item.length or item.l or item[2]
    item.f = nil
    item[1] = nil
    item.l = nil
    item[2] = nil
    if not tonumber(item.freq) or not tonumber(item.length) then
      error("bad table " .. (item.__name or "#" .. num) .. ": expected {number, number}, got {" .. type(item.freq) .. ", " .. type(item.length) .. "}")
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
      return self.data[pos].freq, self.data[pos].length
    else
      return nil
    end
  end
end

Chord.__ipairs = Chord.__pairs



--  Buffer
--    Stores an array of Chords, and its length.
--    Calls a given function when reaches a specific time.

local Buffer = {data={},length=math.huge,func=nil,to=math.huge,pos=1,called=false}
local Buffer.__name = "Buffer"

function Buffer:new(args)
  checkArg(1, args, "table")
  local length = args.length or args.len or args.l
  local func = args.function or args.func
  local to = args.timeout or args.to
  checkType("length", length, "number")
  checkType("func", func, "function")
  checkType("to", to, "number")
  self.length, self.func, self.to = length, func, to
  local o = setmetatable({}, self)
  self.__index = self
  return o
end

function Buffer:seek(pos)
  checkArg(1, pos, "number")
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
  end
  return true
end

function Buffer:play()
  local chords = {}
  for k, v in ipairs(self.data) do
    if v[1].tick == self.pos then
      table.insert(chords, v.chord)
    end
  end
  if self.pos == self.to and not self.called then
    -- Run a new buffer generator function
    self.func(self)
    self.called = false
  end
  self.pos = self.pos + 1
  return chords
end



local function call(class) -- Sugar! Makes a class callable.
  class.__name = class.__name or "<?>"
  class.__tostring = function()
    return "An object \"" .. class.__name .. "\""
  end
  return setmetatable(class, {
    __call = class.new,
    __tostring = function()
      return "A class \"" .. class.__name .. "\""
    end,
    __name = class
  })
end

return {
  Chord = call(Chord)
}

-- vim: expandtab tabstop=2 shiftwidth=2 :

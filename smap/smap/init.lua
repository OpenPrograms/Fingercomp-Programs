-- Big thanks to:
--  * Sangar for his program, midi.lua, a huge part of it was borrowed for midi module,
--  * FluttyProger for helping me to fight against these damn bugs,
--  * TxN for his NBS player code.

local smap = {}

smap.audio = require("smap.audio")
local audio = smap.audio

local fs = require("filesystem")
local pwd = os.getenv("PWD") or "/"

local INPUT = 1
local OUTPUT = 0

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function concat(t1, t2)
  local result = {}
  for k, v in pairs(t1) do
    result[k] = v
  end
  for k, v in pairs(t2) do
    result[k] = v
  end
  return result
end

local function copy(tbl)
  if type(tbl) ~= "table" then
    return tbl
  end
  local result = {}
  for k, v in pairs(tbl) do
    result[k] = copy(v)
  end
  return result
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

local function path(p, ...)
  if p:sub(1, 1) ~= "/" then
    p = fs.concat(pwd, p, ...)
  else
    p = fs.concat(p, ...)
  end
  return p
end

smap.modules = {}
smap.modules.input = {}
local input = smap.modules.input
smap.modules.output = {}
local output = smap.modules.output

local env = {}
local ienv = {}
local oenv = {}

local function addEnv(e)
  local globals = {}
  local o = copy(e)
  setmetatable(o, {
    __index = function(self, k)
      for _, tbl in ipairs({globals, e.TYPE == INPUT and ienv or oenv, env, _G}) do
        if tbl[k] then
          if type(tbl[k]) == "function" then
            return function(...)
              return tbl[k](...)
            end
          else
            return tbl[k]
          end
        end
      end
    end,
    __newindex = globals
  })
  return o, globals
end

env.audio = audio
env.isin = isin
env.getType = getType
env.checkType = checkType
env.copy = copy
env.concat = concat


for _, modtype in pairs({"input", "output"}) do
  for file in fs.list(path("/usr/lib/smap", modtype)) do
    if file:sub(-#("." .. modtype .. ".lua")) == "." .. modtype .. ".lua" then
      local p = path("/usr/lib/smap", modtype, file)
      local mEnv, globals = addEnv({
        _MODULE = file:sub(1, -#file - 1),
        _FILE = file,
        _PATH = p,
        _TYPE = modtype == "input" and INPUT or OUTPUT
      })
      local success, chunk, reason = pcall(loadfile, p, "t", mEnv)
      if not success then
        return false, "fatal", chunk, p
      else
        local success, module = xpcall(chunk, debug.traceback)
        if not success then
          return false, "fatal", module, p
        else
          if globals.NAME and not smap.modules[modtype][globals.NAME] then
            smap.modules[modtype][globals.NAME] = globals
          end
        end
      end
    end
  end
end

function smap.load(path, format)
  checkArg(1, path, "string")
  checkArg(2, format, "string")
  format = format:lower(format)
  if not smap.modules.input[format] then
    return false, "unknown file format"
  end
  if not smap.modules.input[format].loadpath then
    return false, "load is not implemented in module"
  end
  if not fs.exists(path) then
    return false, "no such file"
  end
  return smap.modules.input[format].loadpath(path)
end


function smap.device(dev)
  checkArg(1, dev, "string")
  if not smap.modules.output[dev] then
    return false, "no such device"
  end
  return smap.modules.output[dev].new()
end

return smap

-- vim: expandtab tabstop=2 shiftwidth=2 :

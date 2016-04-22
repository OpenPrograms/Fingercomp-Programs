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

return smap

-- vim: expandtab tabstop=2 shiftwidth=2 :

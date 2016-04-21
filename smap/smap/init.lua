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
  local result
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
  return concat({
    __index = function(self, k)
      for _, tbl in ipairs({globals, e.TYPE == INPUT and ienv or oenv, env}) do
        if tbl[k] then
          if type(tbl[k]) == "function" then
            return function(...)
              return tbl[k](self, ...)
            end
          else
            return tbl[k]
          end
        end
      end
    end,
    __newindex = globals
  }, e), globals
end

function env:setName(name)
  self.__name = name
end

env.audio = audio


for _, modtype in pairs({"input", "output"}) do
  for file in fs.list(path(modtype)) do
    if file:sub(-#("." .. modtype .. ".module")) == "." .. modtype .. ".module" then
      local p = path(modtype, file)
      local mEnv, globals = addEnv({
        _MODULE = file:sub(1, -#a - 1),
        _FILE = file,
        _PATH = p,
        _TYPE = modtype == "input" and INPUT or OUTPUT
      })
      local success, chunk = pcall(loadfile, p, "t", mEnv)
      if not success then
        return false, "fatal", chunk, p
      else
        local success, module = xpcall(chunk, debug.traceback)
        if not success then
          return false, "fatal", module, p
        else
          if mEnv.__name and not smap.module[modtype][mEnv.__name] then
            smap.modules[modtype][mEnv.__name] = globals
          end
        end
      end
    end
  end
end

function smap.load(path, format)
  format = format:lower(format)
  if not smap.modules.input[format] then
    return false, "uncompatible file format"
  end
  if not smap.modules.input[format].load then
    return false, "load is not implemented in module"
  end
  return smap.modules.input[format].load(path)
end

return smap

-- vim: expandtab tabstop=2 shiftwidth=2 :

-- Copyright 2016-2017 Fingercomp

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--     http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local smap = {}

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

local audio

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
      for _, tbl in pairs({globals, e._TYPE == INPUT and ienv or (e._TYPE == OUTPUT and oenv) or {}, env, _G}) do
        if tbl[k] then
          return tbl[k]
        end
      end
    end,
    __newindex = globals
  })
  return o, globals
end

local audio = loadfile("/usr/lib/smap/audio/init.lua", "t", addEnv({_TYPE = 0}))()
smap.audio = audio

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
      if success ~= true then
        return false, "fatal", chunk, p
      else
        local success, module = xpcall(chunk, debug.traceback)
        if success ~= true then
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



function smap.load(p, format)
  checkArg(1, p, "string")
  checkArg(2, format, "string")
  format = format:lower(format)
  if not smap.modules.input[format] then
    return false, "unknown file format"
  end
  if not smap.modules.input[format].loadpath then
    return false, "load is not implemented in module"
  end
  if not fs.exists(p) then
    return false, "no such file"
  end
  return smap.modules.input[format].loadpath(p)
end


function smap.device(dev, addr)
  checkArg(1, dev, "string")
  checkArg(2, addr, "string", "nil")
  if not smap.modules.output[dev] then
    return false, "no such device"
  end
  return smap.modules.output[dev].new(addr)
end

function smap.guessFormat(p)
  checkArg(1, p, "string")
  if not fs.exists(p) then
    return false, "no such file"
  end
  if fs.isDirectory(p) then
    return false, "not a file"
  end
  for module, value in pairs(smap.modules.input) do
    if type(value.guess) == "function" then
      local result = value.guess(p)
      if result then
        return module
      end
    end
  end
  return false, "unknown"
end

return smap

-- vim: expandtab tabstop=2 shiftwidth=2 :

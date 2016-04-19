local smap = {}
smap.__index = smap

smap.audio = require("audio")
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
local inputNames = {}
smap.modules.output = {}
local output = smap.modules.output
local outputNames

local env = {}

local function addEnv(e)
  local globals = {}
  return concat({
    __index = function(self, k)
      for _, tbl in ipairs({e.TYPE == INPUT and ienv or oenv}) do
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
  }, e)
end

function env:setName(name)
  self._name = name
end

for file in filesystem.list(path("input")) do
  if file:sub(-#(".input.module")) == ".input.module" then
    local p = path("input", file)
    local mEnv = addEnv({
      _MODULE = file:sub(1, -#a - 1),
      _FILE = file,
      _PATH = p,
      _TYPE = INPUT
    })
    local success, chunk = pcall(loadfile, p, "t", mEnv)
    if not success then
      io.stderr:write("Could not load an input module \"" .. p .. "\": " .. chunk .. "\n")
    else
      local success, module = xpcall(chunk, debug.traceback)
      if not success then
        io.stderr:write("Could not run an input module \"" .. p .. "\": " .. module .. "\n")
      end
    end
  end
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

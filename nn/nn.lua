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

local CONF = "/etc/nn.conf"

local m = require("component").modem
local event = require("event")
local ser = require("serialization")
local fs = require("filesystem")
local unicode = require("unicode")
_G.port = _G.port or 27091
_G.max = _G.max or 15
_G.effects = _G.effects or {}
_G.effectscomb = _G.effectscomb or {}
_G.groups = _G.groups or {}
_G.init = _G.init or false
_G.nnaddress = _G.nnaddress or false

codes = {
  success    = 0x000,
  fail       = 0x001,
  initfail   = 0x100,
  uninit     = 0x101,
  noresponse = 0x102
}

local function s(...)
  if _G.nnaddress then
    m.send(_G.nnaddress, _G.port, "nanomachines", ...)
  else
    m.broadcast(_G.port, "nanomachines", ...)
  end
end

local function g(...)
  s(...)
  if _G.nnaddress then
    return {event.pull(6, "modem_message", _G.nnaddress)}
  else
    return {event.pull(6, "modem_message")}
  end
end

local function init(rqpt, prpt)
  prpt = prpt or _G.port
  _G.port = rqpt or _G.port
  m.broadcast(prpt, "nanomachines", "setResponsePort", _G.port)
  event.pull(6, "modem_message")
  m.close(prpt)
  m.open(_G.port)
  resp = g("getTotalInputCount") or {}
  _G.max = resp[8]
  if not _G.max then
    io.stderr:write("Failed to init.\n")
    io.write("Are you sure you're near enough to modem and have nanomachines?\n")
    _G.max = 15
    return codes.initfail
  end
  _G.nnaddress = resp[2]
  if fs.exists(CONF) then
    dofile(CONF)
  else
    group = {}
  end
  _G.groups = group
  _G.init = true
  io.write("Configured: PORT " .. _G.port .. ", MAX " .. _G.max .. "\n")
  return codes.success
end

local function isIn(tbl, value)
  for i = 1, #tbl, 1 do
    if tbl[i] == value then
      return true, i
    end
  end
  return false
end

local function test(...)
  if not _G.init then
    io.stderr:write("Run nn init first!\n")
    return -codes.uninit
  end
  local exclude = {...}
  io.write("Starting basic testing\n")
  io.write("Total runs: " .. _G.max .. "\n")
  io.write("Testing starts in 3s...\n")
  os.sleep(3)
  io.write("Beginning test\n")
  _G.effects = {}
  for i = 1, _G.max, 1 do
    if not isIn(exclude, i) then
      io.write("Run #" .. i .. "\n")
      g("setInput", i, true)
      _G.effects[i] = g("getActiveEffects")[8]
      g("setInput", i, false)
      io.write("Effects found:\n")
      io.write(_G.effects[i] .. "\n")
    else
      io.write("Run #" .. i .. " skipped per user's request\n")
    end
  end
  return codes.success
end

local function recurSum(num)
  if num > 0 then
    return num + recurSum(num - 1)
  end
  return 0
end

local function splitComma(str)
  str = str:sub(2, -2)
  local l = {}
  for i in str:gmatch("(.-),.-") do
    table.insert(l, i)
  end
  table.insert(l, str:match(".+,(.+)"))
  if #l == 0 then
    if str ~= "" then
      table.insert(l, str)
    end
  end
  return l
end

local function combotest(...)
  if not _G.init then
    io.stderr:write("Run nn init first!\n")
    return -codes.uninit
  end
  io.write("Combinatoric test\n")
  io.write("Total runs: " .. recurSum(_G.max - 1) .. "\n")
  io.write("It may take very long time!\n")
  io.write("Testing begins is 3s...\n")
  os.sleep(3)
  if #_G.effects == 0 then
    io.write("No input info, starting basic testing\n")
    test(...)
  end
  io.write("Started combinatoric test\n")
  _G.effectscomb = {}
  local exclude = {...}
  for i = 1, _G.max, 1 do
    if not isIn(exclude, i) then
      _G.effectscomb[i] = {}
      io.write("Run #" .. i .. "\n")
      g("setInput", i, true)
      for j = i, _G.max, 1 do
        if i ~= j then
          if not isIn(exclude, j) and not isIn(exclude, i .. "-" .. j) then
            io.write("Run #" .. i .. "." .. j .. "...\n")
            g("setInput", j, true)
            local effComb = g("getActiveEffects")[8] or "{}"
            local effI, effJ = splitComma(_G.effects[i]), splitComma(_G.effects[j])
            local effCombUS = splitComma(effComb)
            local toRemove = {}
            for num, i in ipairs(effI) do
              if isIn(effCombUS, i) then
                table.insert(toRemove, i)
              end
            end
            for num, i in ipairs(toRemove) do
              local _, pos = isIn(effCombUS, i)
              table.remove(effCombUS, pos)
            end
            toRemove = {}
            for num, j in ipairs(effJ) do
              if isIn(effCombUS, j) then
                table.insert(toRemove, j)
              end
            end
            for num, i in ipairs(toRemove) do
              local _, pos = isIn(effCombUS, i)
              table.remove(effCombUS, pos)
            end
            effComb = ser.serialize(effCombUS)
            _G.effectscomb[i][j] = effComb
            io.write("Effects found:\n")
            io.write(_G.effectscomb[i][j] .. "\n")
            g("setInput", j, false)
          else
            io.write("Run #" .. i .. "." .. j .. " skipped per user's request\n")
          end
        end
      end
      g("setInput", i, false)
    else
      io.write("Run #" .. i .. " skipped per user's request\n")
    end
  end
  return codes.success
end

local function reset()
  for i = 1, _G.max, 1 do
    io.write("Turning off #" .. i .. "\n")
    g("setInput", i, false)
  end
  return codes.success
end

local function ge()
  if not _G.init then
    io.stderr:write("Run nn init first!\n")
    return -codes.uninit
  end
  for i = 1, _G.max, 1 do
    if _G.effects[i] then
      io.write("Input #" .. i .. ":\t" .. _G.effects[i] .. "\n")
    end
  end
  return codes.success, _G.effects
end

local function getCombo()
  if not _G.init then
    io.stderr:write("Run nn init first!\n")
    return -codes.uninit
  end
  for numi, i in pairs(_G.effectscomb) do
    for numj, j in pairs(_G.effectscomb[numi]) do
      if j ~= "{}" then
        io.write("Input #" .. numi .. "+" .. numj .. ":\t" .. j .. "\n")
      end
    end
  end
  return codes.success, _G.effectscomb
end

local function clear()
  _G.max, _G.port, _G.effects = 15, 27091, {}
  _G.init, _G.nnaddress = false, false
  return codes.success
end

local function info()
  io.write("PORT: " .. ((_G.port) or "none") .. "\n")
  io.write("MAX: " .. ((_G.max) or "none") .. "\n")
  io.write("EFFECTS: \n")
  return ge()
end

local function gc(...)
  local data = g(...)
  io.write("FROM " .. data[4] .. " in " .. data[5] .. " msg: \n")
  for i = 7, #data, 1 do
    io.write(data[i] .. " ")
  end
  print()
  return codes.success, data
end

local function on(i)
  g("setInput", i, true)
  return codes.success
end

local function off(i)
  g("setInput", i, false)
  return codes.success
end

local function getHP()
  local data = g("getHealth")
  if data then
    io.write("HP: " .. string.rep("♥", data[8]) .. string.rep("♡", data[9] - data[8]) .. " (" .. data[8] .. "/" .. data[9] .. ")\n")
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8], data[9]
end

local function getHung()
  local data = g("getHunger")
  if data then
    io.write("Hunger: " .. data[8] .. " | Saturation: " .. data[9])
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8], data[9]
end

local function getEnergy()
  local data = g("getPowerState")
  if data then
    io.write("↯: " .. data[8] .. "/" .. data[9] .. " (" .. math.floor(data[8] / data[9] * 100) .. "%)\n")
  else
    io.write("Opps, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8], data[9]
end

local function formatNum(num)
  return num > 0 and "+" .. tostring(num) or tostring(num)
end

local function usage()
  io.write("Requesting data...\n")
  local data = {}
  for run = 1, 2, 1 do
    data[run] = g("getPowerState")
    if not data[run] then
      io.write("Oops, no response\n")
      return codes.noresponse
    end
    os.sleep(1)
  end
  io.write("Usage: " .. formatNum(data[2][8] - data[1][8]) .. " per second\n")
  return codes.success, data[2][8] - data[1][8]
end

local function getAge()
  local data = g("getAge")
  if data then
    io.write("Age: " .. data[8] .. "s\n")
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8]
end

local function getName()
  local data = g("getName")
  if data then
    io.write("Player's name is " .. data[8] .. "\n")
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8]
end

local function getInputsInfo()
  local safe = g("getSafeActiveInputs")
  local max = g("getMaxActiveInputs")
  io.write("Safe: " .. (safe[8] or "none") .. ", max: " .. (max[8] or "none") .. "\n")
  return codes.success, safe[8], max[8]
end

local function getActiveEffects()
  local data = g("getActiveEffects")
  if data then
    io.write(data[8] .. "\n")
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success, data[8]
end

local function copy()
  local data = g("saveConfiguration")
  if data then
    if data[8] == false then
      io.stderr("There was a problem: " .. (data[9] or "unknown") .. " \n")
      return codes.fail
    else
      io.write("Copied!\n")
    end
  else
    io.write("Oops, no response\n")
    return codes.noresponse
  end
  return codes.success
end

local function group(...)
  if not _G.init then
    io.stderr:write("Run nn init first!\n")
    return -codes.uninit
  end
  local args = {...}
  local command = args[1]
  table.remove(args, 1)
  if command == "set" then
    local name = args[1]
    table.remove(args, 1)
    local inputs = args
    for num, i in pairs(inputs) do
      if not tonumber(i) then
        table.remove(inputs, num)
      end
    end
    _G.groups[name] = inputs
    io.write("Added group \"" .. name .. "\" with inputs:\t" .. unicode.sub(ser.serialize(inputs), 2, -2) .. "\n")
  elseif command == "del" then
    local name = args[1]
    _G.groups[name] = nil
    io.write("Removed group \"" .. name .. "\"\n")
  elseif command == "save" then
    local f = io.open(CONF, "w")
    f:write("group={")
    local grstr = ""
    for name, value in pairs(groups) do
      grstr = grstr .. "[\"" .. name .. "\"]={"
      for _, i in ipairs(value) do
        grstr = grstr .. i .. ","
      end
      grstr = unicode.sub(grstr, 1, -2) .. "},"
    end
    grstr = unicode.sub(grstr, 1, -2)
    f:write(grstr.."}")
    f:close()
    io.write("Saved to file\n")
  elseif command == "on" or command == "off" then
    local name = args[1]
    table.remove(args, 1)
    if _G.groups[name] then
      for _, i in pairs(_G.groups[name]) do
        if command == "on" then
          on(i)
        else
          off(i)
        end
      end
      io.write("Group \"" .. name .. "\" " .. (command == "on" and "activated" or "disabled") .. "\n")
    end
  elseif command == "list" then
    for name, value in pairs(_G.groups) do
      io.write("Group \"" .. name .. "\":\t" .. unicode.sub(ser.serialize(value), 2, -2) .. "\n")
    end
  end
  return codes.success
end

local function help()
  io.write("Run `man nn` or open /usr/share/doc/nn/README.md for help!\n")
  return codes.success
end

local actions = {
  get = ge,
  clear = clear,
  test = test,
  init = init,
  g = gc,
  s = s,
  reset = reset,
  info = info,
  on = on,
  off = off,
  hp = getHP,
  hunger = getHung,
  energy = getEnergy,
  usage = usage,
  age = getAge,
  name = getName,
  input = getInputsInfo,
  copy = copy,
  efon = getActiveEffects,
  combo = combotest,
  getcombo = getCombo,
  group = group,
  help = help
}

local args = {...}
local command = args[1]
table.remove(args, 1)

for num, i in ipairs(args) do
  if tonumber(i) then
    args[num] = tonumber(i)
  end
end

if not command then
  return actions["init"]()
end
if actions[command] then
  return actions[command](table.unpack(args))
end

-- vim: autoindent expandtab tabstop=2 shiftwidth=2 :

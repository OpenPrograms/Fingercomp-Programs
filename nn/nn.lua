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

local function s(...)
  m.broadcast(_G.port, "nanomachines", ...)
end

local function g(...)
  s(...)
  return {event.pull(6, "modem_message")}
end

local function init(rqpt, prpt)
  _G.port = rqpt or _G.port
  prpt = prpt or _G.port
  m.broadcast(prpt, "nanomachines", "setResponsePort", _G.port)
  event.pull(6, "modem_message")
  m.close(prpt)
  m.open(_G.port)
  _G.max = (g("getTotalInputCount") or {})[8]
  if not _G.max then
    io.stderr:write("Failed to init.\n")
    print("Are you sure you're near enough to a modem and you have nanomachines?")
    return
  end
  if fs.exists(CONF) then
    dofile(CONF)
  else
    group = {}
  end
  _G.groups = group
  print("Configured: PORT " .. _G.port .. ", MAX " .. _G.max)
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
  local exclude = {...}
  print("Starting basic testing")
  print("Total runs: " .. _G.max)
  print("Testing starts in 3s...")
  os.sleep(3)
  print("Beginning test")
  _G.effects = {}
  for i = 1, _G.max, 1 do
    if not isIn(exclude, i) then
      print("Run #" .. i)
      g("setInput", i, true)
      _G.effects[i] = g("getActiveEffects")[8]
      g("setInput", i, false)
      print("Effects found:")
      print(_G.effects[i])
    else
      print("Run #" .. i .. " skipped per user's request")
    end
  end
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
  print("Combinatoric test")
  print("Total runs: " .. recurSum(_G.max - 1))
  print("It may take very long time!")
  print("Testing begins is 3s...")
  os.sleep(3)
  if #_G.effects == 0 then
    print("No input info, starting basic testing")
    test(...)
  end
  print("Started combinatoric test")
  _G.effectscomb = {}
  local exclude = {...}
  for i = 1, _G.max, 1 do
    if not isIn(exclude, i) then
      _G.effectscomb[i] = {}
      print("Run #" .. i)
      g("setInput", i, true)
      for j = i, _G.max, 1 do
        if i ~= j then
          if not isIn(exclude, j) and not isIn(exclude, i .. "-" .. j) then
            print("Run #" .. i .. "." .. j .. "...")
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
            print("Found effects:")
            print(_G.effectscomb[i][j])
            g("setInput", j, false)
          else
            print("Run #" .. i .. "." .. j .. " skipped per user's request")
          end
        end
      end
      g("setInput", i, false)
    else
      print("Run #" .. i .. " skipped per user's request")
    end
  end
end

local function clear()
  for i = 1, _G.max, 1 do
    print("Turning off #" .. i)
    g("setInput", i, false)
  end
end

local function ge()
  for i = 1, _G.max, 1 do
    if _G.effects[i] then
      print("Input #" .. i .. ":\t" .. _G.effects[i])
    end
  end
end

local function getCombo()
  for numi, i in pairs(_G.effectscomb) do
    for numj, j in pairs(_G.effectscomb[numi]) do
      if j ~= "{}" then
        print("Input #" .. numi .. "+" .. numj .. ":\t" .. j)
      end
    end
  end
end

local function reset()
  _G.max, _G.port, _G.effects = 15, 27091, {}
end

local function info()
  print("PORT: " .. _G.port)
  print("MAX: " .. _G.max)
  print("EFFECTS: ")
  ge()
end

local function gc(...)
  local data = g(...)
  io.write("FROM " .. data[4] .. " in " .. data[5] .. " msg: ")
  for i = 7, #data, 1 do
    io.write(data[i] .. " ")
  end
  print()
end

local function on(i)
  g("setInput", i, true)
end

local function off(i)
  g("setInput", i, false)
end

local function getHP()
  local data = g("getHealth")
  io.write("HP: " .. string.rep("♥", data[8]) .. string.rep("♡", data[9] - data[8]) .. " (" .. data[8] .. "/" .. data[9] .. ")\n")
end

local function getHung()
  local data = g("getHunger")
  io.write("Hunger: " .. data[8] .. " | Saturation: " .. data[9])
end

local function getEnergy()
  local data = g("getPowerState")
  io.write("↯: " .. data[8] .. "/" .. data[9] .. " (" .. math.floor(data[8] / data[9] * 100) .. "%)")
end

local function formatNum(num)
  return num > 0 and "+" .. tostring(num) or tostring(num)
end

local function usage()
  print("Requesting data...")
  local data = {}
  for run = 1, 2, 1 do
    data[run] = g("getPowerState")
    os.sleep(1)
  end
  print("Usage: " .. formatNum(data[2][8] - data[1][8]) .. " per second")
end

local function getAge()
  local data = g("getAge")
  io.write("Age: " .. data[8] .. "s")
end

local function getName()
  local data = g("getName")
  io.write("Player's name is " .. data[8])
end

local function getInputsInfo()
  local safe = g("getSafeActiveInputs")
  local max = g("getMaxActiveInputs")
  print("Safe: " .. safe[8] .. ", max: " .. max[8])
end

local function getActiveEffects()
  local data = g("getActiveEffects")
  print(data[8])
end

local function group(...)
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
    print("Added group \"" .. name .. "\" with inputs:\t" .. unicode.sub(ser.serialize(inputs), 2, -2))
  elseif command == "del" then
    local name = args[1]
    _G.groups[name] = nil
    print("Removed group \"" .. name .. "\"")
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
    print("Saved to file")
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
      print("Group \"" .. name .. "\" " .. (command == "on" and "activated" or "disabled"))
    end
  elseif command == "list" then
    for name, value in pairs(_G.groups) do
      print("Group \"" .. name .. "\":\t" .. unicode.sub(ser.serialize(value), 2, -2))
    end
  end
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
  efon = getActiveEffects,
  combo = combotest,
  getcombo = getCombo,
  group = group
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
  actions["init"]()
end
if actions[command] then
  actions[command](table.unpack(args))
end

-- vim: autoindent expandtab tabstop=2 shiftwidth=2 :

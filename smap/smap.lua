local com = require("component")
local comp = require("computer")
local event = require("event")
local fs = require("filesystem")
local kbd = require("keyboard")
local smap = require("smap")
local shell = require("shell")
local term = require("term")

local args, opts = shell.parse(...)

local function help()
  print([[USAGE: smap --d=<device> <input-file> <format>]])
end

if #args ~= 2 or type(opts.d) ~= "string" then
  help()
  return 1
end

local path, format = table.unpack(args)
path = shell.resolve(path)

if not fs.exists(path) then
  print("No such file.")
  return 2
end

local success, reason = smap.load(path, format)
if not success then
  print("Could not load the file: " .. reason .. (reason:sub(-1) ~= "." and "." or ""))
  return 3
end

local music = success

local success, reason = smap.device(opts.d)
if not success then
  print("Could not connect the device: " .. reason .. (reason:sub(-1) ~= "." and "." or ""))
  return 4
end

local device = success

music:connect(device)

print("Playing: " .. path)

local status = 0
local exit = false
local len = math.huge
local x, y = term.getCursor()
local w, h = com.gpu.getResolution()

local function formatTime(t)
  local h = math.floor(t / 3600)
  t = t % 3600
  local m = math.floor(t / 60)
  t = t % 60
  return ("%02d"):format(h) .. ":" .. ("%02d"):format(m) .. ":" .. ("%02d"):format(t)
end

print("Tempo: " .. ("%d"):format(music.track.tempo) .. " ticks per second")

local success, reason = pcall(function()
  local lastSleep = os.clock()
  --local beginUptime = math.floor(comp.uptime())
  local lastTime = -1
  for i = 1, len, 1 do
    if exit then
      break
    end
    local success, reason = music.track:play()
    if not success then
      return success, reason
    end
    for _, dev in pairs(music.devices) do
      dev:play(success)
    end
    local begin = os.clock()
    while os.clock() - begin < 1 / music.track.tempo do
      --if math.floor(comp.uptime() - beginUptime) > lastTime then
      if math.floor(1 / music.track.tempo * i) > lastTime then
        --lastTime = math.floor(comp.uptime() - beginUptime)
        lastTime = math.floor(1 / music.track.tempo * i)
        local length = math.floor(music:getLength() / music.track.tempo)
        com.gpu.fill(1, y, w, 1, " ")
        term.setCursor(1, y)
        io.write("A: " .. formatTime(lastTime) .. " / " .. formatTime(length) .. " (" .. math.floor(lastTime / length * 100) .. "%) [#" .. i .. "]")
      end
      if kbd.isKeyDown(kbd.keys.c) and kbd.isControlDown() then
        os.sleep(.05)
        exit = true
        break
      end
      if os.clock() - lastSleep > 2.5 then
        os.sleep(.05)
        lastSleep = os.clock()
        begin = begin + 0.05
      end
    end
  end
  return true
end)

print("\n")

pcall(music.close, music)

if not success then
  print("An error occured: " .. reason)
  status = -1
else
  print("Exiting...")
end

return status

-- vim: expandtab tabstop=2 shiftwidth=2 :

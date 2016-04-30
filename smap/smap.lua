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
  print("USAGE: smap --d=<device> <input-file> [format]")
end

if #args ~= 1 then
  help()
  return 1
end

if type(opts.d) ~= "string" then
  for name, module in pairs(smap.modules.output) do
    print(" * Module \"" .. name .. "\": " .. (module.DEVICE or "unknown device"))
  end
  return 0
end

local path, format = table.unpack(args)
path = shell.resolve(path)

if not fs.exists(path) then
  print("No such file.")
  return 2
end

local reason
format, reason = format or smap.guessFormat(path)
if not format then
  print("Could not detect file format: " .. reason)
  return 42
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

if music.track.info then
  local info = music.track.info
  if type(info.name) == "string" and info.name ~= "" then
    print("Track name: " .. info.name)
  end
  if type(info.author) == "string" and info.author ~= "" then
    print("Created by: " .. info.author)
  end
  if type(info.comment) == "string" and info.comment ~= "" then
    print(info.comment)
  end
end
print()

local status = 0
local exit = false
local len = math.huge

local function formatTime(t)
  t = math.floor(t)
  local h = math.floor(t / 3600)
  t = t % 3600
  local m = math.floor(t / 60)
  t = t % 60
  return ("%02d"):format(h) .. ":" .. ("%02d"):format(m) .. ":" .. ("%02d"):format(t)
end

print("Tempo: " .. music.track.tempo .. " ticks per second.")

local function onKeyDown()
  if kbd.isKeyDown(kbd.keys.c) and kbd.isControlDown() then
    exit = true
  end
end

local x, y = term.getCursor()
local w, h = com.gpu.getResolution()

event.listen("key_down", onKeyDown)

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
    local pos = music:getPos()
    local begin = os.clock()
    local slept = false
    local sleepTime = 1 / music.track.tempo
    while os.clock() - begin < sleepTime do
      --if math.floor(comp.uptime() - beginUptime) > lastTime then
      if 1 / music.track.tempo * pos - lastTime >= 0.25 then
        --lastTime = math.floor(comp.uptime() - beginUptime)
        lastTime = 1 / music.track.tempo * pos
        local length = music:getLength() / music.track.tempo
        com.gpu.fill(1, y, w, 1, " ")
        term.setCursor(1, y)
        io.write("A: " .. formatTime(lastTime) .. " / " .. formatTime(length) .. " (" .. math.floor(lastTime / length * 100) .. "%) - #" .. pos)
      end
      if exit then
        os.sleep(.05)
        break
      end
      if (opts.sleep == "force" or opts.sleep == "f") and music.track.tempo > 20 then
        io.write("\nThe track is played too fast")
        exit = true
        break
      elseif opts.sleep == "force" or opts.sleep == "f" then
        os.sleep(1 / music.track.tempo)
        break
      end
      if (opts.sleep == "allow" or opts.sleep == "a") and 1 / music.track.tempo * 100 % 5 == 0 then
        os.sleep(1 / music.track.tempo)
        break
      end
      if not slept and (opts.sleep == "allow" or opts.sleep == "none" or opts.sleep == "a" or opts.sleep == "n" or not opts.sleep) and music.track.tempo <= 10 then
        local toSleep = math.floor(1 / music.track.tempo * 100) == 1 / music.track.tempo * 100 and 1 / music.track.tempo - 0.05 or math.floor(1 / music.track.tempo * 100) / 100
        os.sleep(toSleep)
        sleepTime = sleepTime - toSleep
        slept = true
      end
      if os.clock() - lastSleep > 1 then
        os.sleep(.05)
        lastSleep = os.clock()
        sleepTime = sleepTime - 0.05
      end
    end
  end
  return true
end)

event.ignore("key_down", onKeyDown)

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

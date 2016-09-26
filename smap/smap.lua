-- Copyright 2016 Fingercomp

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--     http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.local com = require("component")

local comp = require("computer")
local event = require("event")
local fs = require("filesystem")
local kbd = require("keyboard")
local smap = require("smap")
local shell = require("shell")
local term = require("term")

local DEBUG = true
local args, opts = shell.parse(...)

local function dbg(...)
  if not DEBUG then return end
  print(table.concat({...}, "\t"))
end

local function help()
  print([[USAGE: smap [--sleep=<mode>] --d=<device> <input-file> [format]
--sleep=<mode>: <mode> may be one of these values:
 * `force` or `f`: force os.sleep()'ing, will not play tracks with the tempo more than 20 tps.
 * `allow` or `a`: allow to use os.sleep() to make a delay between ticks
 * `none` or `n`: use os.sleep() only to make partial delays. Default.
 * `deny` or `d`: don't use os.sleep(), busy-idle instead. High CPU usage.]])
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

local success, reason = smap.device(opts.d)
if not success then
  print("Could not connect the device: " .. reason .. (reason:sub(-1) ~= "." and "." or ""))
  return 3
end

local device = success

local success, reason = smap.load(path, format)
if not success then
  reason = reason or "unknown reason"
  print("Could not load the file: " .. reason .. (reason:sub(-1) ~= "." and "." or ""))
  return 4
end

local music = success

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
local paused = false
local forceUpdate = false

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
  elseif kbd.isKeyDown(kbd.keys.space) then
    paused = not paused
    forceUpdate = true
  end
end

local x, y = term.getCursor()
local w, h = com.gpu.getResolution()

event.listen("key_down", onKeyDown)

local success, reason = pcall(function()
  local lastSleep = os.clock()
  local lastTime = -1
  local lastTick = 0
  -- FIXME: MAKE IT WORK
  for i = 1, len, 1 do
    if exit then
      break
    end
    local success, reason = music.track:play()
    if not success then
      return success, reason
    end
    if not (#success == 0 and (i - lastTick) / music.track.tempo < .25) then
      for _, dev in pairs(music.devices) do
        dev:play(success)
      end
      local pos = music:getPos()
      local begin = os.clock()
      local slept = false
      local sleepTime = (i - lastTick) / music.track.tempo
      lastTick = i
      local u1 = comp.uptime()
      while os.clock() - begin < sleepTime do
        if 1 / music.track.tempo * pos - lastTime >= .25 or forceUpdate then
          lastTime = 1 / music.track.tempo * pos
          local length = music:getLength() / music.track.tempo
          com.gpu.fill(1, y, w, 1, " ")
          term.setCursor(1, y)
          io.write((paused and "(Paused) " or "") .. "A: " .. formatTime(lastTime) .. " / " .. formatTime(length) .. " (" .. math.floor(lastTime / length * 100) .. "%) - #" .. pos)
          forceUpdate = false
        end
        if exit then
          os.sleep(.05)
          break
        end
        if paused then
          local c1 = os.clock()
          os.sleep(.1)
          lastSleep = os.clock()
          sleepTime = sleepTime + lastSleep - c1
        else
          if (opts.sleep == "force" or opts.sleep == "f") and sleepTime < .05 then
            io.write("\nThe track is played too fast")
            exit = true
            break
          elseif opts.sleep == "force" or opts.sleep == "f" then
            os.sleep(sleepTime)
            lastSleep = os.clock()
            break
          end
          if (opts.sleep == "allow" or opts.sleep == "a") and sleepTime * 100 % 5 == 0 then
            os.sleep(sleepTime)
            lastSleep = os.clock()
            break
          end
          if not slept and (opts.sleep == "allow" or opts.sleep == "none" or opts.sleep == "a" or opts.sleep == "n" or not opts.sleep) and sleepTime >= .1 then
            local toSleep = math.floor((sleepTime - .05) * 20) / 20
            local c1 = os.clock()
            dbg("\n\t" .. toSleep, sleepTime)
            os.sleep(toSleep)
            lastSleep = os.clock()
            sleepTime = sleepTime - toSleep
            begin = begin + os.clock() - c1
            slept = true
          end
          if os.clock() - lastSleep > 1 then
            local c1 = os.clock()
            os.sleep(.05)
            lastSleep = os.clock()
            sleepTime = sleepTime - 0.05
            begin = begin + os.clock() - c1
          end
        end
      end
      dbg("\n" .. sleepTime, comp.uptime() - u1)
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

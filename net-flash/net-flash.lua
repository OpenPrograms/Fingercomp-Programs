local com = require("component")
local comp = require("computer")
local event = require("event")
local serialization = require("serialization")
local shell = require("shell")

local modem = com.modem

local args, options = shell.parse(...)
if #args ~= 1 then
  io.stderr:write([==[
Usage: net-flash [--c=<chunk size>]
                 [--port=<port>]
                 [{-r|--response=<timeout>}]
                 [--addr=<remote address>] <source>
]==])
  return 1
end

local function send(port, ...)
  if type(options.addr) == "string" then
    modem.send(options.addr, port, ...)
  else
    send(port, ...)
  end
end

local input = io.stdin
if args[1] ~= "-" then
  local reason
  input, reason = io.open(args[1], "r")
  if not input then
    io.stderr:write("Could not open file for writing: " .. tostring(reason) .. "\n")
    return 2
  end
end

local bios = input:read("*a")
input:close()

local chunks = {}
local chunkSize = tonumber(options.c or options.chunk)
if not chunkSize then
  local deviceInfo = comp.getDeviceInfo()[modem.address]
  chunkSize = deviceInfo.capacity - 1024
end

for i = 1, #bios, chunkSize do
  table.insert(chunks, bios:sub(i, i + chunkSize - 1))
end

local port = tonumber(options.p or options.port) or 1370
for i = 1, #chunks, 1 do
  local isEnd = i == #chunks
  send(port, "net-eeprom", "eeprom", isEnd, chunks[i])
end

if options.r or options.response then
  local wasOpen = modem.isOpen(port)
  if not wasOpen then
    modem.open(port)
  end
  local timeout = tonumber(options.r) or tonumber(options.response) or math.huge
  local addr = type(options.addr) == "string" and options.addr or nil
  local e = {event.pull(timeout, "modem_message", _, addr, port, _, "net-eeprom")}
  if e[1] then
    if e[7] == "success" then
      local lastNonNil = 8
      for i = 13, 8, -1 do
        if e[i] ~= nil then
          lastNonNil = i
          break
        end
      end
      local response = {}
      for i = 8, lastNonNil, 1 do
        table.insert(response, serialization.serialize(e[i]))
      end
      io.stdout:write("Success\t" .. table.concat(response, "\t") .. "\n")
    else
      io.stdout:write("Error\t" .. e[8] .. "\t" .. (e[9] ~= nil and tostring(e[9]) or "") .. "\n")
    end
  end
end

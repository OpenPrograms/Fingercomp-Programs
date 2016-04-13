assert(_OSVERSION == "OpenOS 1.6", "This program requires OpenOS 1.6!")

local term = require("term")
local com = require("component")

local function reqcom(componentName, message)
  if not com.isAvailable(componentName) then
    io.stderr:write(message or "Component \"" .. componentName .. "\" is unavailable!")
    return -1
  end
  return com[componentName]
end

local modem = reqcom("modem", "This program requires a network card!")

local gpu = com.gpu

if modem.isWireless() then
  modem.setStrength(400)
end

-- vim: expandtab tabstop=2 shiftwidth=2 autoindent :

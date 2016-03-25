assert(_OSVERSION == "OpenOS 1.6", "This program requires OpenOS 1.6!")
local com = require("component")
local event = require("event")
local guid = require("guid")

local function reqcom(componentName, req, msg)
  if not com.isAvailable(componentName) then
    if req then
      io.stderr:write((msg or "No such component: " .. componentName .. "!") .. "\n")
      os.exit(-1)
    else
      msg and io.stderr:write(msg .. "\n")
      return setmetatable({}, {
        __tostring = function(self)
          return "This is a dummy component"
        end,
        __index = function(self, k)
          if k == "address" then
            return guid.next()
          elseif k == "slot" then
            return -1
          elseif k == "type" then
            return componentName
          else
            return function()
              return
            end
          end
        end
      })
    end
  end
  return component[componentName]
end

local bridge = reqcom("openperipheral_bridge", true, "This program needs Openperipheral bridge to work!")

local surfaces = {
  _ = {}
}

local coreHandlers = {
  glasses_attach = {
    function(event, addr, user, uuid)
      surfaces[user] = bridge.getSurfaceByName(user)
    end
  },
  glasses_detach = {
  }
}

for eventName, hdlrs in pairs(coreHandlers) do
  for hdlr in pairs(hdlrs) do
    event.listen(eventName, hdlr)
  end
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

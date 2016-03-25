assert(_OSVERSION == "OpenOS 1.6", "This program requires OpenOS 1.6!")
local com = require("component")
local event = require("event")
local guid = require("guid")
local fs = require("filesystem")

local modulesPath = "/usr/lib/chat-modules/"
local env = {}

local function reqcom(componentName, req, msg)
  if not com.isAvailable(componentName) then
    if req then
      io.stderr:write((msg or "No such component: " .. componentName .. "!") .. "\n")
      os.exit(-1)
    else
      local _ = msg and io.stderr:write(msg .. "\n")
      _ = nil
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
  return com[componentName]
end

local bridge = reqcom("openperipheral_bridge", true, "This program needs Openperipheral bridge to work!")

local surfaces = {}

local chatLines = {}

local function addObject(surface, name, func, ...)
  local args = {...}
  local reason
  if name then
    surface.objects[name], reason = surface.surface[func](table.unpack(args))
  else
    surface.objects.insert(surface.surface[func](table.unpack(args)))
  end
  if reason then
    print(reason)
  end
  surface.objects[name].setUserdata({name = name})
  return surface.objects[name]
end

local function drawChat(surface)
  addObject(surface, "chat.box.chat", "addBox", 5, 55, 400, 120, 0x282828, .8)
  addObject(surface, "chat.box.topic", "addBox", 5, 45, 400, 11, 0x404040, .8)
  addObject(surface, "chat.box.userlist", "addBox", 410, 35, 100, 150, 0x282828, .8)
  addObject(surface, "chat.box.input", "addBox", 5, 175, 400, 10, 0x404040, .8)
  addObject(surface, "chat.line.nick", "addLine", {x=105, y=55}, {x=105,y=185}, 0x20afff, .8)
  addObject(surface, "chat.line.input", "addLine", {x=5, y=175}, {x=405,y=175}, 0x20afff, .8)
  addObject(surface, "chat.line.topic", "addLine", {x=5, y=55}, {x=405, y=55}, 0x20afff, .8)
  addObject(surface, "chat.line.userlist", "addLine", {x=410, y=45}, {x=510, y=45}, 0x20afff, .8)
  for i = 1, 9, 1 do
    local start = (i - 1) * 45 + 5
    addObject(surface, "chat.poly.chan." .. i, "addPolygon", 0x105888, .8, {x=start, y=45}, {x=start, y=37}, {x=start+2, y=35}, {x=start+38, y=35}, {x=start+40, y=37}, {x=start+40, y=45}).setVisible(false)
    addObject(surface, "chat.poly.chan." .. i .. ".active", "addPolygon", 0x101010, .8, {x=start, y=37}, {x=start, y=34}, {x=start+2, y=32}, {x=start+38, y=32}, {x=start+40, y=34}, {x=start+40, y=37}, {x=start+38, y=35}, {x=start+2, y=35}).setVisible(false)
    local chanText = addObject(surface, "chat.text.chan." .. i, "addText", start+2, 37, "", 0xffffff)
    chanText.setScale(.75)
    chanText.setVisible(false)
  end
  addObject(surface, "chat.text.userlist", "addText", 412, 37, "Users:", 0x20afff).setScale(.75)
  for i = 1, 14 do
    local start = (i - 1) * 10 + 47
    addObject(surface, "chat.text.users." .. i, "addText", 412, start, "", 0xffffff).setScale(.75)
  end
  for i = 1, 12 do
    local start = (i - 1) * 10 + 57
    addObject(surface, "chat.text.lines." .. i .. ".nick", "addText", 7, start, "", 0xffffff).setScale(.75)
    addObject(surface, "chat.text.lines." .. i .. ".msg", "addText", 107, start, "", 0xffffff).setScale(.75)
  end
  addObject(surface, "chat.text.input.nick", "addText", 7, 177, "", 0xffffff).setScale(.75)
  addObject(surface, "chat.text.input.input", "addText", 107, 177, "", 0xd3d3d3).setScale(.75)
  addObject(surface, "chat.text.topic", "addText", 7, 47, "", 0xffffff).setScale(.75)
end

local moduleHandlers = {}

function env.addListener(eventName, func)
  moduleHandlers[eventName] = moduleHandlers[eventName] or {}
  moduleHandlers[eventName].insert(func)
end

local coreHandlers = {
  chat_init = {
    function(evt, time)
      bridge.clear()
      for _, user in pairs(bridge.getUsers()) do
        user = user.name
        surfaces[user] = {surface = bridge.getSurfaceByName(user)}
        surfaces[user].objects = {}
        drawChat(surfaces[user])
      end
    end
  },
  glasses_attach = {
    function(evt, addr, user, uuid)
      surfaces[user] = {surface = bridge.getSurfaceByName(user)}
      surfaces[user].surface.clear()
      surfaces[user].objects = {}
      drawChat(surfaces[user])
    end
  },
  glasses_detach = {
    function(evt, addr, user, uuid)
      local _ = surfaces[user] and surfaces[user].surface and surfaces[user].surface.clear()
      surfaces[user] = nil
    end
  },
  chat_update = {
    function(evt, time, tick)
      if tick % 10 == 0 then
        bridge.sync()
      end
    end
  },
  chat_stop = {
    function(evt, time)
      bridge.clear()
    end
  },
  chat_load = function(evt, time)
    for file in fs.list(modulesPath) do
      local chunk, reason = loadfile(fs.concat(modulesPath, file), nil, nil, setmetatable({}, {
        __index = function(self, k)
          if isin(env, k) then
            return env[k]
          else
            return _G[k]
          end
        end
      }))
      if not chunk then
        io.stderr:write("Failed to load module \"" .. file .. "\": " .. (reason or "no reason") .. "\n")
      else
        local success, reason = xpcall(chunk, function(exception)
          return "Exception in module \"" .. file .. "\": " .. exception .. "!\n" .. debug.traceback() .. "\n"
        end)
        if not success then
          io.stderr:write(reason)
        end
      end
    end
  end
}

for eventName, hdlrs in pairs(coreHandlers) do
  for id, hdlr in pairs(hdlrs) do
    print("Starting \"" .. eventName .. "\" listener [" .. id .. "]")
    event.listen(eventName, hdlr)
  end
end

print("init")
event.push("chat_init", os.time())
os.sleep(.5) -- Allow to process init

print("load")
event.push("chat_load", os.time())
os.sleep(.5)

print("start")
event.push("chat_start", os.time())
os.sleep(.5)

local tick = 0
local upd = event.timer(.1, function()
  event.push("chat_update", os.time(), tick)
end, math.huge)

os.sleep(5)

print("stop")
event.push("chat_stop", os.time())
os.sleep(.5)

for eventName, hdlrs in pairs(coreHandlers) do
  for id, hdlr in pairs(hdlrs) do
    print("Stopping \"" .. eventName .. "\" listener [" .. id .. "]")
    event.ignore(eventName, hdlr)
  end
end

event.cancel(upd)

-- vim: expandtab tabstop=2 shiftwidth=2 :

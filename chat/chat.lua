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
      _ = msg and io.stderr:write(msg .. "\n")
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

local surfaces = {
  _ = {}
}

local function addObject(surface, name, ...)
  local args = {...}
  local func = args[1]
  table.remove(args, 1)
  if name then
    surface.objects[name] = surface.surface[func](table.unpack(args))
  else
    surface.objects.insert(surface.surface[func](table.unpack(args)))
  end
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
    addObject(surface, "chat.poly.chan." .. i, "addPolygon", 0x105888, .8, {x=start, y=45}, {x=start, y=37}, {x=start+2, y=35}, {x=start+38, y=35}, {x=start+40, y=37}, {x=start+40, y=45})
    addObject(surface, "chat.poly.chan." .. i .. ".active", "addPolygon", 0x101010, .8, {x=start, y=37}, {x=start, y=34}, {x=start+2, y=32}, {x=start+38, y=32}, {x=start+40, y=34}, {x=start+40, y=37}, {x=start+38, y=35}, {x=start+2, y=35})
    addObject(surface, "chat.text.chan." .. i, "addText", start+2, 37, "#test", 0xffffff).setScale(.75)
  end
  addObject(surface, "chat.text.userlist", "addText", 412, 37, "Users:", 0x20afff).setScale(.75)
  for i = 1, 14 do
    local start = (i - 1) * 10 + 47
    addObject(surface, "chat.text.users." .. i, "addText", 412, start, "someGuy", 0xffffff).setScale(.75)
  end
  for i = 1, 12 do
    local start = (i - 1) * 10 + 57
    addObject(surface, "chat.text.lines." .. i .. ".nick", "addText", 7, start, "§a@§fFingercomp", 0xffffff).setScale(.75)
    addObject(surface, "chat.text.lines." .. i .. ".msg", "addText", 107, start, "Some text here", 0xffffff).setScale(.75)
  end
  addObject(surface, "chat.text.input.nick", "addText", 7, 177, "§a@§fFingercomp", 0xffffff).setScale(.75)
  addObject(surface, "chat.text.input.input", "addText", 107, 177, "Msg2send", 0xd3d3d3).setScale(.75)
  addObject(surface, "chat.text.topic", "addText", 7, 47, "Topic for §3#test§f", 0xffffff).setScale(.75)
end

local coreHandlers = {
  init = {
    function(event, time)
      bridge.clear()
      for _, user in pairs(bridge.getUsers()) do
        user = user.name
        surfaces[user] = surfaces[user] or {surface = bridge.getSurfaceByName(user)}
        surfaces[user].objects = surfaces[user].objects or {}
        drawChat(surfaces[user])
      end
    end
  },
  glasses_attach = {
    function(event, addr, user, uuid)
      surfaces[user] = surfaces[user] or {surface = bridge.getSurfaceByName(user)}
      surfaces[user].objects = surfaces[user].objects or {}
      drawChat(surfaces[user])
    end
  },
  glasses_detach = {
    function(event, addr, user, uuid)
      local _ = surfaces[user] and surfaces[user].clear()
      surfaces[user] = nil
    end
  },
  start = {
    function()
      bridge.sync()
    end
  }
}

for eventName, hdlrs in pairs(coreHandlers) do
  for id, hdlr in pairs(hdlrs) do
    event.listen(eventName, hdlr)
  end
end

print("init")
event.push("init", os.time())
os.sleep(.5) -- Allow to process init

print("load")
event.push("load", os.time())
os.sleep(.5)

print("start")
event.push("start", os.time())
os.sleep(.5)

for eventName, hdlrs in pairs(coreHandlers) do
  for _, hdlr in pairs(hdlrs) do
    event.ignore(eventName, hdlr)
  end
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

assert(_OSVERSION == "OpenOS 1.6", "This program requires OpenOS 1.6!")
local com = require("component")
local event = require("event")
local guid = require("guid")
local unicode = require("unicode")
local fs = require("filesystem")
local text = require("text")

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

local NORMAL, VOICE, HALFOP, OP = 0, 1, 2, 3

local PREFIXES = {
  [0] = "",
  "§e+§f",
  "§2!§f",
  "§a@§f"
}

local notifications = {
  join_chan = {pattern = "§6%s§f joined %s", nick = "§2-->"},
  part_chan = {pattern = "§6%s§f left %s", nick = "§4<--"},
  quit = {pattern = "§6%s§f quit the server", nick = "§4<--"}
}

local pms = {}
local users = {}
local channels = {}

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function addObject(surface, name, func, ...)
  checkArg(1, surface, "table")
  checkArg(2, name, "string", "nil")
  checkArg(3, func, "string")
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
    addObject(surface, "chat.poly.chans." .. i, "addPolygon", 0x105888, .8, {x=start, y=45}, {x=start, y=37}, {x=start+2, y=35}, {x=start+38, y=35}, {x=start+40, y=37}, {x=start+40, y=45}).setVisible(false)
    addObject(surface, "chat.poly.chans." .. i .. ".active", "addPolygon", 0x101010, .8, {x=start, y=37}, {x=start, y=34}, {x=start+2, y=32}, {x=start+38, y=32}, {x=start+40, y=34}, {x=start+40, y=37}, {x=start+38, y=35}, {x=start+2, y=35}).setVisible(false)
    local chanText = addObject(surface, "chat.text.chans." .. i, "addText", start+2, 37, "", 0xffffff)
    chanText.setScale(.75)
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

local function createChannel(chan, nick)
  checkArg(1, chan, "string")
  checkArg(2, nick, "string")
  assert(users[nick], "no such nickname")
  assert(chan:sub(1, 1) == "#", "not a channel")
  channels[chan] = {
    info = {
      ["creation-date"] = os.date("%Y-%m-%d %H:%M:%S")
    },
    users = {
      [nick] = NORMAL
    },
    lines = {},
    modes = {},
    topic = ""
  }
  table.insert(users[nick].channels, chan)
end

local function addUser(user)
  checkArg(1, user, "string")
  assert(not users[user], "user already exists")
  users[user] = {
    channels = {},
    modes = {},
    prompt = {},
    history = {},
    tabStart = 1,
    currentTab = 1,
    channelOffsets = {}
  }
end

local function join(chan, user)
  checkArg(1, chan, "string")
  checkArg(2, user, "string")
  assert(chan:sub(1, 1) == "#", "not a channel")
  assert(users[user], "no such nickname")
  assert(not isin(users[user].channels, chan), "alreay in the channel")
  if not channels[chan] then
    createChannel(chan, user)
  else
    channels[chan].users[user] = NORMAL
    table.insert(users[user].channels, chan)
  end
  users[user].channelOffsets[chan] = 1
  users[user].prompt[chan] = {"", 1, 1}
end

local function part(chan, user)
  checkArg(1, chan, "string")
  checkArg(2, user, "string")
  assert(channels[chan], "no such channel")
  assert(users[user], "no such nickname")
  assert(channels[chan].users[user], "user is not in channel")
  channels[chan].users[user] = nil
  local _, pos = isin(users[user].channels, chan)
  table.remove(users[user].channels, pos)
end

local function sendMsgChan(chan, nick, msg, rec)
  checkArg(1, chan, "string")
  checkArg(2, nick, "string")
  checkArg(3, msg, "string")
  checkArg(4, rec, "table", "nil")
  assert(chan:sub(1, 1) == "#", "not a channel")
  assert(channels[chan], "no such channel")
  assert(users[nick], "no such nickname")
  local date = os.date("%Y-%m-%d %H:%M:%S")
  rec = rec or "all"
  table.insert(channels[chan].lines, {date = date, nick, msg, rec})
end

local function sendNotifyChan(chan, notify, parts, rec)
  checkArg(1, chan, "string")
  checkArg(2, notify, "string")
  checkArg(3, parts, "table")
  checkArg(4, rec, "table", "nil")
  assert(chan:sub(1, 1) == "#", "not a channel")
  assert(channels[chan], "no such channel")
  assert(notifications[notify], "no such notification")
  local date = os.date("%Y-%m-%d %H:%M:%S")
  rec = rec or "all"
  table.insert(channels[chan].lines, {date = date, notify = {notify, parts}, rec})
end

local function sendPM(addressee, nick, msg)
  checkArg(1, addressee, "string")
  checkArg(2, nick, "string")
  checkArg(3, msg, "string")
  assert(users[addressee], "no such user")
  assert(users[nick], "no such nickname")
  local date = os.date("%Y-%m-%d %H:%M:%S")
  local pmList = {addressee, nick}
  table.sort(pmList)
  local pmName = table.concat(pmList, "\0")
  pms[pmName] = pms[pmName] or {members = {addressee, nick}}
  table.insert(pms[pmName], {date = date, nick, addressee, msg})
end

local function joinN(chan, user)
  join(chan, user)
  sendNotifyChan(chan, "join_chan", {user, chan})
end

local function partN(chan, user)
  part(chan, user)
  sendNotifyChan(chan, "part_chan", {user, chan})
end

local function quitN(user)
  for _, chan in pairs(users[user].channels) do
    part(chan, user)
    sendNotifyChan(chan, "quit", {user})
  end
end

local function getActiveChannel(user)
  local active = users[user].currentTab
  local showTabUserdata = surfaces[user].objects["chat.text.chans." .. active].getUserdata()
  if showTabUserdata and showTabUserdata.chan then
    return showTabUserdata.chan
  else
    return false
  end
end

local moduleHandlers = {}
local commands = {}

env.getActiveChannel = getActiveChannel
env.createChannel = createChannel
env.addUser = addUser
env.join = join
env.part = part
env.sendMsgChan = sendMsgChan
env.sendNotifyChan = sendNotifyChan
env.sendPM = sendPM
env.joinN = joinN
env.partN = partN
env.quitN = quitN
env.addObject = addObject
env.bridge = bridge
env.surfaces = surfaces
env.users = users
env.pms = pms
env.channels = channels
env.commands = commands
env._MODULE = ""
env._FILE = ""
env.NORMAL = NORMAL
env.VOICE = VOICE
env.HALFOP = HALFOP
env.OP = OP
env.PREFIXES = PREFIXES

function env.addListener(eventName, name, func)
  checkArg(1, eventName, "string")
  checkArg(2, name, "string")
  checkArg(3, func, "function")
  if moduleHandlers[eventName] and moduleHandlers[eventName][name] then
    assert(false, "ununique name!")
  end
  moduleHandlers[eventName] = moduleHandlers[eventName] or {}
  moduleHandlers[eventName][name] = func
end

function env.delListener(eventName, name)
  checkArg(1, eventName, "string")
  checkArg(2, name, "string")
  if moduleHandlers[eventName][name] then
    event.ignore(eventName, moduleHandlers[eventName][name])
    moduleHandlers[eventName][name] = nil
  end
end

function command(setEnv)
  return function(args)
    checkArg(1, args, "table")
    local name, level, help, doc, aliases, func = args.name, args.level, args.help, args.doc, args.aliases, args.func
    local errorPattern = "\"%s\": %s expected, %s given"
    assert(type(name) == "string", errorPattern:format("name", "string", type(name)))
    assert(type(level) == "number", errorPattern:format("level", "number", type(level)))
    assert(isin({"nil", "string"}, type(help)), errorPattern:format("help", "string or nil", type(help)))
    assert(isin({"nil", "string"}, type(doc)), errorPattern:format("doc", "string or nil", type(doc)))
    assert(isin({"table", "nil"}, type(aliases)), errorPattern:format("aliases", "table or nil", type(aliases)))
    assert(type(func) == "function", errorPattern:format("func", "function", type(func)))
    commands[name] = {level = level, help = help, doc = doc, aliases = aliases, func = func}
    local cmds = {name, table.unpack(aliases or {})}
    for _, cmd in pairs(cmds) do
      setEnv.addListener("chat_shash_cmd_" .. cmd, setEnv._MODULE .. ".commands." .. name .. "." .. cmd, func)
    end
  end
end

local coreHandlers = {
  chat_init = {
    function(evt, time)
      addUser("%SERVER")
      join("#main", "%SERVER")
      channels["#main"].users["%SERVER"] = OP
      bridge.clear()
      for _, user in pairs(bridge.getUsers()) do
        user = user.name
        surfaces[user] = {surface = bridge.getSurfaceByName(user)}
        surfaces[user].objects = {}
        drawChat(surfaces[user])
        addUser(user)
        joinN("#main", user)
      end
    end
  },
  glasses_attach = {
    function(evt, addr, user, uuid)
      surfaces[user] = {surface = bridge.getSurfaceByName(user)}
      surfaces[user].surface.clear()
      surfaces[user].objects = {}
      drawChat(surfaces[user])
      if not users[user] then
        addUser(user)
      end
      joinN("#main", user)
    end
  },
  glasses_detach = {
    function(evt, addr, user, uuid)
      local _ = surfaces[user] and surfaces[user].surface and surfaces[user].surface.clear()
      surfaces[user] = nil
      if users[user] then
        quitN(user)
      end
    end
  },
  chat_update = {
    function(evt, time, tick)
      if tick % 10 == 0 then
        for user, surface in pairs(surfaces) do
          local userinfo = users[user]
          if not userinfo then goto nextUser end
          
          -- 1. TABS
          -- 1.1. Set tabs
          local chans = userinfo.channels
          chans = table.pack(table.unpack(chans, userinfo.tabStart, userinfo.tabStart + 10))
          for i, chan in pairs(chans) do
            if i ~= "n" then
              if #chan > 11 then
                chanLabel = chan:sub(1, 10) .. "…"
              else
                chanLabel = chan
              end
              local textObj = surface.objects["chat.text.chans." .. i]
              if textObj.getText() ~= chanLabel then
                textObj.setText(chanLabel)
                local userdata = textObj.getUserdata() or {}
                userdata.chan = chan
                textObj.setUserdata(userdata)
              end
              surface.objects["chat.poly.chans." .. i].setVisible(true)
              surface.objects["chat.poly.chans." .. i .. ".active"].setVisible(false)
            end
          end

          -- 1.2. Hide unused tabs
          if #userinfo.channels < 10 then
            local start = #userinfo.channels + 1
            for i = start, 9, 1 do
              surface.objects["chat.poly.chans." .. i].setVisible(false)
              local userdata = surface.objects["chat.text.chans." .. i].getUserdata() or {}
              userdata.chan = nil
              surface.objects["chat.text.chans." .. i].setUserdata(userdata)
              surface.objects["chat.poly.chans." .. i .. ".active"].setVisible(false)
            end
          end

          -- 1.3. Select active tab
          local showTab = getActiveChannel(user)
          if not showTab then
            goto nextUser
          end
          local active = userinfo.currentTab
          surface.objects["chat.poly.chans." .. active .. ".active"].setVisible(true)


          -- 2. MSG AREA
          -- 2.1. Get lines to show
          local toShow = {}
          local lines = channels[showTab].lines
          local offset = userinfo.channelOffsets[showTab]
          for i = 1, #lines - offset + 1, 1 do
            local line = lines[i]
            local date, nick, msg, rec, notify = line.date, nil, nil, nil, line.notify
            if not notify then
              nick, msg, rec = line[1], line[2], line[3]
            else
              rec = line[1]
            end
            if rec == "all" or isin(rec, user) then
              if not notify then
                local userPrefix = PREFIXES[channels[showTab].users[nick] or NORMAL]
                local msglines = {}
                for msgline in text.wrappedLines(msg, 67, 67) do
                  table.insert(msglines, msgline)
                end
                if #msglines == 1 then
                  table.insert(toShow, {nick = userPrefix .. nick, msg = msg})
                else
                  local wrapped = {}
                  for i = #msglines, 1, -1 do
                    msg = msglines[i]
                    local nickText = i == 1 and (userPrefix .. nick) or ""
                    table.insert(wrapped, {nick = nickText, msg = msg})
                  end
                  for wrI = #wrapped, 1, -1 do
                    table.insert(toShow, wrapped[wrI])
                  end
                end
              else
                msg = notifications[notify[1]].pattern:format(table.unpack(notify[2]))
                table.insert(toShow, {nick = notifications[notify[1]].nick, msg = msg})
              end
            end
          end
          
          -- 2.2. Show 'em all
          for i = 12, 1, -1 do
            local line = toShow[#toShow + i - 12]
            if not line then break end
            local nick = surface.objects["chat.text.lines." .. i .. ".nick"]
            local msg = surface.objects["chat.text.lines." .. i .. ".msg"]
            if #line.nick > 20 then
              line.nick = line.nick:sub(1, 19) .. "…"
            end if #line.msg > 67 then -- Should not ever happen, just to be on the safe side
              line.msg = line.msg:sub(1, 67)
            end
            if nick.getText() ~= line.nick then
              nick.setText(line.nick)
            end if msg.getText() ~= line.msg then
              msg.setText(line.msg)
            end
          end


          -- 3. TOPIC
          local topic = channels[showTab].topic
          if unicode.len(topic) > 100 then
            topic = unicode.sub(topic, 1, 99) .. "…"
          end
          if surface.objects["chat.text.topic"].getText() ~= topic then
            surface.objects["chat.text.topic"].setText(topic)
          end


          -- 4. USERLIST
          local users = channels[showTab].users
          local i = 1
          for nick, prefix in pairs(users) do
            if i > 14 then break end
            local name = PREFIXES[prefix] .. nick
            if surface.objects["chat.text.users." .. i].getText() ~= name then
              surface.objects["chat.text.users." .. i].setText(name)
            end
            i = i + 1
          end
          for j = i, 14, 1 do
            if surface.objects["chat.text.users." .. j].getText() ~= "" then
              surface.objects["chat.text.users." .. j].setText("")
            end
          end


          ::nextUser::
        end
      end
    end,
    function(evt, time, tick)
      for user, surface in pairs(surfaces) do
        local showTab = getActiveChannel(user)
        local userinfo = users[user]
        local name = user:sub(1, 20)
        if surface.objects["chat.text.input.nick"].getText() ~= name then
          surface.objects["chat.text.input.nick"].setText(name)
        end
        local prompt = userinfo.prompt[showTab] or {"", 1, 1}
        local inputLine = prompt[1] .. " "
        local curPos, offset = prompt[2], prompt[3]
        curPos = curPos - offset + 1
        inputLine = unicode.sub(inputLine, offset, offset + 65)
        inputLine = unicode.sub(inputLine, 1, curPos - 1) .. "§n" .. unicode.sub(inputLine, curPos, curPos) .. "§r" .. unicode.sub(inputLine, curPos + 1)
        local input = surface.objects["chat.text.input.input"]
        if input.getText() ~= inputLine then
          input.setText(inputLine)
        end
      end
    end,
    function(evt, time, tick)
      if (tick + 5) % 10 == 0 then
        bridge.sync()
      end
    end
  },
  chat_stop = {
    function(evt, time)
      bridge.clear()
      bridge.sync()
    end
  },
  chat_load = {
    function(evt, time)
      for file in fs.list(modulesPath) do
        if file:match("%.([^.]+)$") == "module" then
          local module = file:match("^[^.]+")
          local moduleEnv = setmetatable(env, {__index = _G})
          moduleEnv._MODULE = module
          moduleEnv._FILE = file
          moduleEnv.command = command(moduleEnv)
          local chunk, reason = loadfile(fs.concat(modulesPath, file), nil, moduleEnv)
          if not chunk then
            io.stderr:write("Failed to load module \"" .. file .. "\": " .. (reason or "no reason") .. "\n")
          else
            local success, reason = xpcall(chunk, function(exception)
              return "Exception in module \"" .. file .. "\": " .. exception .. "!\n" .. debug.traceback() .. "\n"
            end)
            if not success then
              io.stderr:write(reason)
            else
              event.push("chat_loaded_module", file, os.time())
            end
          end
        end
      end
    end
  }
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

for eventName, hdlrs in pairs(moduleHandlers) do
  for name, hdlr in pairs(hdlrs) do
    print("Starting module \"" .. eventName .. "\" listener [" .. name .. "]")
    event.listen(eventName, hdlr)
  end
end

print("start")
event.push("chat_start", os.time())
os.sleep(.5)

local tick = 0
local upd = event.timer(.1, function()
  event.push("chat_update", os.time(), tick)
  tick = tick + 1
end, math.huge)

repeat
  local keyDownData = {event.pull("key_down")}
until keyDownData[1] == "key_down"

print("stop")
event.push("chat_stop", os.time())
os.sleep(.5)

for eventName, hdlrs in pairs(moduleHandlers) do
  for name, hdlr in pairs(hdlrs) do
    print("Stopping module \"" .. eventName .. "\" listener [" .. name .. "]")
    event.ignore(eventName, hdlr)
  end
end

for eventName, hdlrs in pairs(coreHandlers) do
  for id, hdlr in pairs(hdlrs) do
    print("Stopping \"" .. eventName .. "\" listener [" .. id .. "]")
    event.ignore(eventName, hdlr)
  end
end

event.cancel(upd)

-- vim: expandtab tabstop=2 shiftwidth=2 :

assert(_OSVERSION == "OpenOS 1.6", "This program requires OpenOS 1.6!")
local com = require("component")
local event = require("event")
local guid = require("guid")
local unicode = require("unicode")
local fs = require("filesystem")
local text = require("text")

local modulesPath = "/usr/lib/chat-modules/"
local env = {}
local config = "/etc/chat.json"

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

if not fs.exists("/usr/lib/json.lua") then
  local inet = reqcom("internet", true, "This program need an internet card to install json lib!")
  if not fs.exists("/usr/lib") then
    fs.makeDirectory("/usr/lib")
  end
  local request = inet.request("http://regex.info/code/JSON.lua")
  local file = io.open("/usr/lib/json.lua", "w")
  while true do
    local chunk = request.read()
    if not chunk then break end
    file:write(chunk)
  end
  file:close()
end

local bridge = reqcom("openperipheral_bridge", true, "This program needs Openperipheral bridge to work!")

local json = require("json")

-- Let's load the config right here to be sure
-- program can access it if I'd need it somewhere in program init
local cfg = {}
do
  local f = io.open(config, "r")
  local all = f:read("*a")
  f:close()
  cfg = json:decode(all)
end

local surfaces = {}

local NORMAL  = 0x0
local VOICE   = 0x1
local HALFOP  = 0x2
local OP      = 0x4
local ADMIN   = 0x8
local SERVER  = 0x10

local PREFIXES = {
  [NORMAL] = "",
  [VOICE] = "§e+§f",
  [HALFOP] = "§2!§f",
  [OP] = "§a@§f"
}

local notifications = {
  join_chan = {pattern = "§6%s§f joined %s", nick = "§2-->"},
  part_chan = {pattern = "§6%s§f left %s (%s)", nick = "§4<--"},
  quit = {pattern = "§6%s§f quit the server (%s)", nick = "§4<--"},
  pm = {pattern = "§3%s§6 → §3%s§f: %s", nick = "§3--"},
  topic = {pattern = "§6%s§f changed topic to: \"%s\"", nick = "§5**"},
  mode = {pattern = "§6%s§f set modes [%s %s]", nick = "§5**"}
}

local modes = {}
local users = {}
local channels = {}

local codePtn = "§[%xoklmn]"

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function stripCodes(line)
  return line:gsub(codePtn, "")
end

local function getLineLen(line)
  return unicode.len(stripCodes(line))
end

local function subLine(line, p1, p2)
  local result = {}
  local code = ""
  for i = 1, unicode.len(line), 1 do
    local prev, sym, nxt = unicode.sub(line, i - 1, i - 1), unicode.sub(line, i, i), unicode.sub(line, i + 1, i + 1)
    if prev and (prev .. sym):match(codePtn) then
      code = prev .. sym
    elseif not (sym .. nxt):match(codePtn) then
      result[#result] = code .. sym
      code = ""
    end
  end
  return table.concat(result, "")
end

local function wrap(line, width)
  local result = {}
  for i = 1, unicode.len(line), width do
    table.insert(result, text.trim(unicode.sub(line, i, i + width - 1)))
  end
  return result
end

local function getLevel(chan, user)
  local level = NORMAL
  if not users[user] then return level end
  if cfg.server == user then
    level = level + SERVER
  end
  if isin(cfg.admins, user) then
    level = level + ADMIN
  end
  if not channels[chan] or not channels[chan].users[user] then
    return level
  end
  return level + channels[chan].users[user]
end

local function checkLevel(chan, user, levels, any)
  local proceed = true
  local userLevel = getLevel(chan, user)
  for _, level in pairs(levels) do
    if userLevel & level == level then
      if any then
        return true
      end
    else
      proceed = false
    end
  end
  return proceed
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
  end
  addObject(surface, "chat.text.userlist", "addText", 412, 37, "Users:", 0x20afff)
  for i = 1, 14 do
    local start = (i - 1) * 10 + 47
    addObject(surface, "chat.text.users." .. i, "addText", 412, start, "", 0xffffff)
  end
  for i = 1, 12 do
    local start = (i - 1) * 10 + 57
    addObject(surface, "chat.text.lines." .. i .. ".nick", "addText", 7, start, "", 0xffffff)
    addObject(surface, "chat.text.lines." .. i .. ".msg", "addText", 107, start, "", 0xffffff)
  end
  addObject(surface, "chat.text.input.nick", "addText", 7, 177, "", 0xffffff)
  addObject(surface, "chat.text.input.input", "addText", 107, 177, "", 0xd3d3d3)
  addObject(surface, "chat.text.topic", "addText", 7, 47, "", 0xffffff)
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
  event.push("chat_event_createChannel", os.time(), chan, nick)
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
    shown = true,
    channelOffsets = {}
  }
end

local function join(chan, user)
  checkArg(1, chan, "string")
  checkArg(2, user, "string")
  assert(chan:sub(1, 1) == "#", "not a channel")
  assert(users[user], "no such nickname")
  assert(not isin(users[user].channels, chan), "already in the channel")
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
  table.insert(channels[chan].lines, {date = date, level = channels[chan].users[nick], nick, msg, rec})
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
  sendNotifyChan("#main", "pm", {addressee, nick, msg}, {nick})
  event.push("chat_event_pm", os.time(), addressee, nick, msg)
end

modes.o = function(chan, user, set, arg)
  if not arg then return false end
  assert(channels[chan].users[arg], "no such user")
  assert(checkLevel(chan, user, {OP, ADMIN, SERVER}, true), "no permission")
  local was = channels[chan].users[arg]
  channels[chan].users[arg] = set and OP or NORMAL
  if was ~= channels[chan].users[arg] then
    return true
  end
end

modes.h = function(chan, user, set, arg)
  if not arg then return false end
  assert(channels[chan].users[arg], "no such user")
  assert(checkLevel(chan, user, {OP, ADMIN, SERVER}, true) or checkLevel(chan, user, {HALFOP}, true) and user == arg, "no permission")
  local was = channels[chan].users[arg]
  channels[chan].users[arg] = set and HALFOP or NORMAL
  if was ~= channels[chan].users[arg] then
    return true
  end
end

modes.v = function(chan, user, set, arg)
  if not arg then return false end
  assert(channels[chan].users[arg], "no such user")
  assert(checkLevel(chan, user, {OP, ADMIN, SERVER}, true) or checkLevel(chan, user, {VOICE, HALFOP}, true) and user == arg)
  local was = channels[chan].users[arg]
  channels[chan].users[arg] = set and VOICE or NORMAL
  if was ~= channels[chan].users[arg] then
    return true
  end
end

modes.t = function(chan, user, set)
  assert(checkLevel(chan, user, {OP, ADMIN, SERVER}, true), "no permission")
  if set and not isin(channels[chan].modes, "t") then
    table.insert(channels[chan].modes, "t")
  else
    local _, pos = isin(channels[chan].modes, "t")
    if pos then
      table.remove(channels[chan].modes, pos)
    else
      return false
    end
  end
  return true
end

local function setMode(chan, user, mode, arg)
  checkArg(1, chan, "string")
  checkArg(2, user, "string")
  checkArg(3, mode, "string")
  checkArg(4, arg, "string", "nil")
  assert(channels[chan], "no such channel")
  assert(mode:match("^[+-].$"), "wrong mode")
  local set = mode:sub(1, 1) == "+"
  mode = mode:sub(2)
  assert(modes[mode], "unknown mode")
  local success = modes[mode](chan, user, set, arg)
  if success then
    local modeStr = (set and "+" or "-") .. mode .. (arg and " " .. arg or "")
    sendNotifyChan(chan, "mode", {user, chan, modeStr})
  end
end

local function joinN(chan, user)
  join(chan, user)
  sendNotifyChan(chan, "join_chan", {user, chan})
  event.push("chat_event_join", os.time(), chan, user)
end

local function partN(chan, user, reason)
  reason = reason or ""
  part(chan, user)
  sendNotifyChan(chan, "part_chan", {user, chan, reason})
  event.push("chat_event_part", os.time(), chan, user, reason)
end

local function quitN(user, reason)
  reason = reason or ""
  for _, chan in pairs(users[user].channels) do
    part(chan, user)
    sendNotifyChan(chan, "quit", {user, reason})
  end
  event.push("chat_event_quit", os.time(), user, reason)
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
env.isin = isin
env.cfg = cfg
env.setMode = setMode
env.modes = modes
env.getLevel = getLevel
env.checkLevel = checkLevel
env._MODULE = ""
env._FILE = ""
env.NORMAL = NORMAL
env.VOICE = VOICE
env.HALFOP = HALFOP
env.OP = OP
env.ADMIN = ADMIN
env.SERVER = SERVER
env.PREFIXES = PREFIXES

function env.apcall(func, ...)
  local data = {pcall(func, ...)}
  if data[1] then
    return true, table.unpack(data, 2)
  end
  local reason = data[2]
  reason = reason:match("^.+:%d+:%s(.+)$")
  if reason then
    return false, reason, table.unpack(data, 3)
  end
  return false, table.unpack(data, 2)
end

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

local function cmdWrapper(cmdInfo)
  return function(evt, chan, user, cmd, ...)
    if checkLevel(chan, user, cmdInfo.level, true) then
      cmdInfo.func(evt, chan, user, cmd, ...)
    else
      sendPM(user, cfg.server, "no permission")
    end
  end
end

local function command(setEnv)
  return function(args)
    checkArg(1, args, "table")
    local name, level, help, doc, aliases, func = args.name, args.level, args.help, args.doc, args.aliases, args.func
    local errorPattern = "\"%s\": %s expected, %s given"
    assert(type(name) == "string", errorPattern:format("name", "string", type(name)))
    assert(isin({"table", "number"}, type(level)), errorPattern:format("level", "table or number", type(level)))
    assert(isin({"nil", "string"}, type(help)), errorPattern:format("help", "string or nil", type(help)))
    assert(isin({"nil", "string"}, type(doc)), errorPattern:format("doc", "string or nil", type(doc)))
    assert(isin({"table", "nil"}, type(aliases)), errorPattern:format("aliases", "table or nil", type(aliases)))
    assert(type(func) == "function", errorPattern:format("func", "function", type(func)))
    if type(level) == "number" then
      local levels = {NORMAL, VOICE, HALFOP, OP, ADMIN, SERVER}
      local _, pos = isin(levels, level)
      assert(pos, "wrong level")
      for i = 1, pos - 1, 1 do
        table.remove(levels, 1)
      end
      level = levels
    end
    commands[name] = {level = level, help = help, doc = doc, aliases = aliases, func = func}
    local cmds = {name, table.unpack(aliases or {})}
    for _, cmd in pairs(cmds) do
      env.addListener("chat_slash_cmd_" .. cmd, setEnv._MODULE .. ".commands." .. name .. "." .. cmd, cmdWrapper(commands[name]))
    end
  end
end

function env.help(user, cmd)
  checkArg(1, user, "string")
  checkArg(2, cmd, "string")
  assert(users[user], "no such user")
  assert(commands[cmd], "no such command")
  sendPM(cfg.server, user, "Help (" .. cmd .. "): " .. (commands[cmd].help or ""))
end

local coreHandlers = {
  chat_init = {
    function(evt, time)
      addUser(cfg.server)
      join("#main", cfg.server)
      channels["#main"].users[cfg.server] = OP
      bridge.clear()
      for _, user in pairs(bridge.getUsers()) do
        user = user.name
        surfaces[user] = {surface = bridge.getSurfaceByName(user)}
        surfaces[user].objects = {}
        drawChat(surfaces[user])
      end
    end
  },
  chat_start = {
    function(evt, time)
      for user in pairs(surfaces) do
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
      if tick % 5 == 0 then
        for user, surface in pairs(surfaces) do
          local userinfo = users[user]
          if not userinfo then goto nextUser end
          if not userinfo.shown then goto nextUser end
          
          -- 1. TABS
          -- 1.1. Set tabs
          local chans = userinfo.channels
          chans = table.pack(table.unpack(chans, userinfo.tabStart, userinfo.tabStart + 10))
          for i, chan in pairs(chans) do
            if i ~= "n" then
              if #chan > 6 then
                chanLabel = chan:sub(1, 5) .. "…"
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
              surface.objects["chat.text.chans." .. i].setText("")
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
          for i = 1, #lines, 1 do
            local line = lines[i]
            local date, nick, msg, rec, notify = line.date, nil, nil, nil, line.notify
            if not notify then
              nick, msg, rec = line[1], line[2], line[3]
            else
              rec = line[1]
            end
            if rec == "all" or isin(rec, user) then
              local name = ""
              if not notify then
                local userPrefix = PREFIXES[line.level or NORMAL]
                name = (userPrefix or "") .. nick
              else
                msg = notifications[notify[1]].pattern:format(table.unpack(notify[2]))
                name = notifications[notify[1]].nick
              end
              local msglines = wrap(msg, 49)
              if #msglines == 1 then
                table.insert(toShow, {nick = name, msg = msg})
              else
                local wrapped = {}
                for i = #msglines, 1, -1 do
                  local nickText = i == 1 and name or ""
                  msg = msglines[i]
                  table.insert(wrapped, {nick = nickText, msg = msg})
                end
                for wrI = #wrapped, 1, -1 do
                  table.insert(toShow, wrapped[wrI])
                end
              end
            end
          end
          for i = #lines - offset + 2, #lines, 1 do
            table.remove(toShow, #lines - offset + 2)
          end
          
          -- 2.2. Show 'em all
          for i = 12, 1, -1 do
            local line = toShow[#toShow + i - 12]
            line = line or {}
            line.nick = line.nick or ""
            line.msg = line.msg or ""
            local nick = surface.objects["chat.text.lines." .. i .. ".nick"]
            local msg = surface.objects["chat.text.lines." .. i .. ".msg"]
            if getLineLen(line.nick) > 16 then
              line.nick = subLine(line.nick, 1, 15) .. "…"
            end
            if nick.getText() ~= line.nick then
              nick.setText(line.nick)
            end if msg.getText() ~= line.msg then
              msg.setText(line.msg)
            end
          end


          -- 3. TOPIC
          local topic = channels[showTab].topic
          if getLineLen(topic) > 66 then
            topic = subLine(topic, 1, 65) .. "…"
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
            if getLineLen(name) > 16 then
              name = subLine(name)
            end
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
        local userinfo = users[user]
        if not userinfo then goto nextInputUser end
        local showTab = getActiveChannel(user)
        if not showTab then goto nextInputUser end
        local name = unicode.sub(user, 1, 16)
        if surface.objects["chat.text.input.nick"].getText() ~= name then
          surface.objects["chat.text.input.nick"].setText(name)
        end
        local prompt = userinfo.prompt[showTab] or {"", 1, 1}
        local inputLine = prompt[1] .. " "
        local curPos, offset = prompt[2], prompt[3]
        curPos = curPos - offset + 1
        inputLine = unicode.sub(inputLine, offset, offset + 48)
        inputLine = unicode.sub(inputLine, 1, curPos - 1) .. "§n" .. unicode.sub(inputLine, curPos, curPos) .. "§r" .. unicode.sub(inputLine, curPos + 1)
        local input = surface.objects["chat.text.input.input"]
        if input.getText() ~= inputLine then
          input.setText(inputLine)
        end

        ::nextInputUser::
      end
    end,
    function(evt, time, tick)
      bridge.sync()
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

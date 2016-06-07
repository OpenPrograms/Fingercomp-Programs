local com = require("component")
local event = require("event")
local unicode = require("unicode")
local fs = require("filesystem")
local text = require("text")
local srl = require("serialization")

local modulesPath = "/usr/lib/chat-modules/"
local env = {}
local config = "/etc/opg-chat.json"
local exit = false
local openos = _OSVERSION == "OpenOS 1.6" and "1.6" or (_OSVERSION == "OpenOS 1.5" and "1.5" or (io.stderr:write("Warning: unknown OS! The program may eventually crash or work incorrectly.\n") and "1.5" or "1.5"))
local guid = {
  toHex = function(n)
    if type(n) ~= 'number' then
      return nil, string.format("toHex only converts numbers to strings, %s is not a string, but a %s", tostring(n), type(n))
    end
    if n == 0 then
      return '0'
    end

    local hexchars = "0123456789abcdef"
    local result = ""
    local prefix = "" -- maybe later allow for arg to request 0x prefix
    if n < 0 then
      prefix = "-"
      n = -n
    end

    while n > 0 do
      local next = math.floor(n % 16) + 1 -- lua has 1 based array indices
      n = math.floor(n / 16)
      result = hexchars:sub(next, next) .. result
    end

    return prefix .. result
  end,
  next = function()
    -- e.g. 3c44c8a9-0613-46a2-ad33-97b6ba2e9d9a
    -- 8-4-4-4-12
    local sets = {8, 4, 4, 12}
    local result = ""

    local i
    for _,set in ipairs(sets) do
      if result:len() > 0 then
        result = result .. "-"
      end
      for i = 1,set do
        result = result .. guid.toHex(math.random(0, 15))
      end
    end

    return result
  end
}

event.push = event.push or require("computer").pushSignal

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
      }), false
    end
  end
  return com[componentName], true
end

if not fs.exists("/usr/lib/json.lua") then
  local inet = reqcom("internet", true, "This program needs an internet card to install json lib!")
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

local bridge = reqcom("openperipheral_bridge", true, "This program needs an Openperipheral bridge to work!")

local json = require("json")

if not fs.exists(config) then
  local f = io.open(config, "w")
  f:write(json:encode_pretty({
    server = "%SERVER%",
    admins = {"Fingercomp"},
    main_channel = "#main",
    net = {
      enabled = true,
      modem_strength = 400,
      ports = {
        ["6667"] = true,
        ["6666"] = {"244d"}
      },
      ping = {
        enabled = true,
        interval = 180,
        timeout = 180
      }
    },
    users = {},
    max_chan_lines = 750
  }))
  f:close()
  print("No configuration file found, created a new one. Path to the config: " .. config)
  print("Edit the settings and relaunch the program.")
  return 0
end

-- Let's load the config here to be sure the program
-- can access it if I'd need it somewhere in program init
local cfg = {}
do
  local f = io.open(config, "r")
  local all = f:read("*a")
  f:close()
  cfg = json:decode(all)
  if not cfg.main_channel:match("^#%w[%w%._]*$") then
    io.stderr:write("invalid main channel name, expected \"^#%w[%w%._]*$\". Fix your configuration file.")
  end
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
  [HALFOP] = "§2%§f",
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

local function band(...)
  local bit32 = bit32 or require("bit32")
  return bit32.band(...)
end

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function copy(tbl)
  if type(tbl) ~= "table" then
    return tbl
  end
  local result = {}
  for k, v in pairs(tbl) do
    result[k] = copy(v)
  end
  return result
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
      table.insert(result, code .. sym)
      code = ""
    end
  end
  for i = p2 + 1, #result, 1 do
    table.remove(result)
  end
  for i = 1, p1 - 1, 1 do
    table.remove(result, 1)
  end
  return table.concat(result, "")
end

local function wrap(line, width)
  local result = {}
  for i = 1, getLineLen(line), width do
    local wrappedLine = text.trim(subLine(line, i, i + width - 1))
    if wrappedLine ~= "" then
      table.insert(result, wrappedLine)
    end
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
    if band(userLevel, level) == level then
      if any then
        return true
      end
    else
      proceed = false
    end
  end
  return proceed
end

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

local function truncate(chan)
  while #channels[chan].lines > cfg.max_chan_lines do
    local ntcs, msgs = 0, 0
    for k, v in pairs(channels[chan].lines) do
      if (v.notify and v[1] or v[3]) ~= "all" then
        ntcs = ntcs + 1
      else
        msgs = msgs + 1
      end
    end
    local rmMsg = msgs > ntcs
    for i = 1, #channels[chan].lines, 1 do
      local inV = channels[chan].lines[i]
      if (inV.notify and inV[1] or inV[3]) ~= "all" and not rmMsg or
          (inV.notify and inV[1] or inV[3]) == "all" and rmMsg then
        table.remove(channels[chan].lines, i)
        break
      end
    end
  end
end

local function createChannel(chan, nick)
  checkArg(1, chan, "string")
  checkArg(2, nick, "string")
  assert(users[nick], "no such nickname")
  assert(chan:sub(1, 1) == "#", "not a channel")
  assert(chan:match("^#%w[%w%._]*$"), "invalid chars in chan name")
  channels[chan] = {
    info = {
      ["creation-date"] = os.date("%Y-%m-%d %H:%M:%S")
    },
    users = {
      [nick] = NORMAL
    },
    lines = {},
    modes = {},
    topic = "",
    banned = {},
    exempt = {}
  }
  table.insert(users[nick].channels, chan)
  event.push("chat_event_createChannel", os.time(), chan, nick)
end

local function addUser(user, isNetUser)
  checkArg(1, user, "string")
  checkArg(2, isNetUser, "boolean", "nil")
  -- TODO kick net users if normal one tries to connect
  assert(not users[user], "user already exists")
  cfg.users[user] = cfg.users[user] or {
    pass = ""
  }
  users[user] = {
    channels = {},
    modes = {},
    prompt = {},
    history = {},
    tabStart = 1,
    currentTab = 1,
    shown = true,
    channelOffsets = {},
    cfg = cfg.users[user],
    net = isNetUser or false
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
  users[user].history[chan] = {pos = 0}
end

local function part(chan, user)
  checkArg(1, chan, "string")
  checkArg(2, user, "string")
  assert(channels[chan], "no such channel")
  assert(users[user], "no such nickname")
  assert(channels[chan].users[user], "user is not in the channel")
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
  truncate(chan)
  event.push("chat_event_msg", os.time(), chan, nick, msg, rec == "all" or #rec, table.unpack(type(rec) == "all" and {rec} or rec))
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
  truncate(chan)
  event.push("chat_event_notice", os.time(), chan, notify, notifications[notify].pattern:format(table.unpack(parts)), rec == "all" or #rec, table.unpack(rec == "all" and {rec} or rec), srl.serialize(parts))
end

local function sendPM(addressee, user, msg)
  checkArg(1, addressee, "string")
  checkArg(2, user, "string")
  checkArg(3, msg, "string")
  assert(users[addressee], "no such user")
  assert(users[user], "no such nickname")
  sendNotifyChan(cfg.main_channel, "pm", {user, addressee, msg}, {user, addressee})
  event.push("chat_event_pm", os.time(), user, addressee, msg)
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
  assert(checkLevel(chan, user, {OP, ADMIN, SERVER}, true) or checkLevel(chan, user, {VOICE, HALFOP}, true) and user == arg, "no permission")
  local was = channels[chan].users[arg]
  channels[chan].users[arg] = set and VOICE or NORMAL
  if was ~= channels[chan].users[arg] then
    return true
  end
end

local function togglableMode(mode, level, any)
  checkArg(1, mode, "string")
  checkArg(2, level, "table")
  checkArg(3, soft, "boolean", "nil")
  any = any or true
  return function(chan, user, set, arg)
    assert(checkLevel(chan, user, level, any), "no permission")
    if set and not isin(channels[chan].modes, mode) then
      table.insert(channels[chan].modes, mode)
    else
      local _, pos = isin(channels[chan].modes, mode)
      if pos then
        table.remove(channels[chan].modes, pos)
      else
        return false
      end
    end
   return true
 end
end

modes.t = togglableMode("t", {OP, ADMIN, SERVER})
modes.m = togglableMode("m", {HALFOP, OP, ADMIN, SERVER})

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
  local chans = users[user].channels
  reason = reason or ""
  for i = #chans, 1, -1 do
    local chan = chans[i]
    part(chan, user)
    sendNotifyChan(chan, "quit", {user, reason})
  end
  users[user] = nil
  event.push("chat_event_quit", os.time(), user, reason, table.unpack(chans))
end

local function sendMsgChanN(chan, user, msg)
  if isin(channels[chan].modes, "m") and not checkLevel(chan, user, {VOICE, HALFOP, OP}, true) then
    sendPM(user, cfg.server, "The channel is moderated")
    return -1
  end
  if isin(channels[chan].banned, user) and not isin(channels[chan].exempt, user) and not checkLevel(chan, user, {HALFOP, OP, ADMIN, SERVER}) then
    sendPM(user, cfg.server, "You are banned from the channel")
    return -1
  end
  local success, reason = env.apcall(sendMsgChan, chan, user, msg)
  if not success then
    sendPM(user, cfg.server, "Could not send message: " .. reason)
  end
end

local function getActiveChannel(user)
  local active = users[user].currentTab
  return users[user].channels[active] or false
end

local moduleHandlers = {}
local commands = {}
local storage = {}

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
env.sendMsgChanN = sendMsgChanN
env.addObject = addObject
env.bridge = bridge
env.surfaces = surfaces
env.users = users
env.channels = channels
env.commands = commands
env.isin = isin
env.cfg = cfg
env.setMode = setMode
env.modes = modes
env.getLevel = getLevel
env.checkLevel = checkLevel
env.togglableMode = togglableMode
env.storage = storage
env.reqcom = reqcom
env.copy = copy
env._MODULE = ""
env._FILE = ""
env.NORMAL = NORMAL
env.VOICE = VOICE
env.HALFOP = HALFOP
env.OP = OP
env.ADMIN = ADMIN
env.SERVER = SERVER
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

local function cmdWrapper(cmdInfo)
  return function(evt, chan, user, raw, cmd, ...)
    if checkLevel(chan, user, cmdInfo.level, true) then
      cmdInfo.func(evt, chan, user, raw, cmd, ...)
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
  if commands[cmd].doc then
    local docStr = commands[cmd].doc
    local doc = {""}
    for i = 1, unicode.len(docStr), 1 do
      local sym = unicode.sub(docStr, i, i)
      if sym == "\n" then
        doc[#doc+1] = ""
      else
        doc[#doc] = doc[#doc] .. sym
      end
    end
    for _, line in ipairs(doc) do
      sendPM(user, cfg.server, "> " .. line)
    end
  end
end

local function saveCfg()
  local content = json:encode_pretty(cfg)
  local f = io.open(config, "r")
  local backup = io.open(config .. ".backup", "w")
  backup:write(f:read("*a"))
  backup:close()
  f:close()
  f = io.open(config, "w")
  f:write(content)
  f:close()
end

local coreHandlers = {
  chat_init = {
    function(evt, time)
      addUser(cfg.server)
      join(cfg.main_channel, cfg.server)
      channels[cfg.main_channel].users[cfg.server] = OP
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
        joinN(cfg.main_channel, user)
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
      joinN(cfg.main_channel, user)
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
          for i, chan in ipairs(chans) do
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
          if offset > #toShow - 11 then
            users[user].channelOffsets[showTab] = #toShow - 11
            offset = #toShow - 11
          end
          for i = #lines - offset + 2, #lines, 1 do
            table.remove(toShow, #toShow)
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
    end,
    function(evt, time, tick)
      if tick % 600 == 0 then
        saveCfg()
      end
    end
  },
  chat_stop = {
    function(evt, time)
      exit = true
    end,
    function(evt, time)
      bridge.clear()
      bridge.sync()
    end,
    function(evt, time)
      saveCfg()
    end
  },
  chat_load = {
    function(evt, time)
      for file in fs.list(modulesPath) do
        if file:match("%.([^.]+)$") == "module" then
          local module = file:match("^[^.]+")
          storage.module = {}
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
    --print("Starting \"" .. eventName .. "\" listener [" .. id .. "]")
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
    --print("Starting module \"" .. eventName .. "\" listener [" .. name .. "]")
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

while not exit do
  os.sleep(.1)
end

os.sleep(.5)

for eventName, hdlrs in pairs(moduleHandlers) do
  for name, hdlr in pairs(hdlrs) do
    --print("Stopping module \"" .. eventName .. "\" listener [" .. name .. "]")
    event.ignore(eventName, hdlr)
  end
end

for eventName, hdlrs in pairs(coreHandlers) do
  for id, hdlr in pairs(hdlrs) do
    --print("Stopping \"" .. eventName .. "\" listener [" .. id .. "]")
    event.ignore(eventName, hdlr)
  end
end

event.cancel(upd)

-- vim: expandtab tabstop=2 shiftwidth=2 :

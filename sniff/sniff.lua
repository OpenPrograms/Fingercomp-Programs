local com = require("component")
local event = require("event")
local term = require("term")
local comp = require("computer")
local forms = require("forms")

local gpu = com.gpu

local oldW, oldH = gpu.getResolution()
local oldFG = gpu.getForeground()
local oldBG = gpu.getBackground()

gpu.setResolution(80, 25)

forms.ignoreAll()
local elements = {}

local main = forms.addForm()
main.color = 0x333333
elements.main = main

local topFrame = main:addFrame(1, 1, 0)
topFrame.W = 80
topFrame.H = 1
topFrame.color = 0xCCCCCC
topFrame.fontColor = 0
elements.topFrame = topFrame

local appName = topFrame:addLabel(3, 1, "NETWORK SNIFFER")
appName.color = 0xCCCCCC
appName.fontColor = 0
elements.appName = appName

local function updateMsgData()
  local self = elements.msgList
  elements.msgTime.caption =     "TIME:     " .. self.items[self.index][1]
  elements.recvAddr.caption = "RECEIVER: " .. self.items[self.index][2]
  elements.sendAddr.caption = "SENDER:   " .. self.items[self.index][3]
  elements.port.caption =     "PORT:     " .. self.items[self.index][4]
  elements.distance.caption = "DISTANCE: " .. self.items[self.index][5]
  elements.chunkList:clear()
  for i = 6, #self.items[self.index], 1 do
    elements.chunkList:insert("#" .. tostring(i - 5), self.items[self.index][i])
  end
  if self.items[self.index][6] then
    elements.data:setTextHex(self.items[self.index][6])
  end
  elements.chunkCount.caption = ("%3d"):format(#self.items[self.index] - 5)
  elements.msgInfo:redraw()
end

local function update()
  if not elements.msgInfo.visible then
    elements.msgInfo:show()
    updateMsgData()
  else
    elements.msgInfo:redraw()
  end
end

local msgList = main:addList(1, 2, updateMsgData)
msgList.sfColor = 0x000000
msgList.selColor = 0xFFFFFF
msgList.color = 0x333333
msgList.border = 0
msgList.W = 80
msgList.H = 9
elements.msgList = msgList

local msgInfo = main:addFrame(1, 11, 0)
msgInfo.H = 15
msgInfo.color = 0xCCCCCC
msgInfo.W = 80
msgInfo:hide()
elements.msgInfo = msgInfo

local msgTime = msgInfo:addLabel(3, 1, "TIME: ")
msgTime.fontColor = 0x000000
msgTime.color = 0xCCCCCC
msgTime.W = 7
elements.msgTime = msgTime

local recvAddr = msgInfo:addLabel(3, 2, "RECEIVER: ")
recvAddr.fontColor = 0x000000
recvAddr.color = 0xCCCCCC
recvAddr.W = 7
elements.recvAddr = recvAddr

local sendAddr = msgInfo:addLabel(3, 3, "SENDER: ")
sendAddr.fontColor = 0x000000
sendAddr.color = 0xCCCCCC
sendAddr.W = 7
elements.sendAddr = sendAddr

local distance = msgInfo:addLabel(3, 4, "DISTANCE: ")
distance.fontColor = 0x000000
distance.color = 0xCCCCCC
distance.W = 10
elements.distance = distance

local port = msgInfo:addLabel(3, 5, "PORT: ")
port.fontColor = 0x000000
port.color = 0xCCCCCC
port.W = 6
elements.port = port

local data = msgInfo:addList(3, 6, function() end)
data.H = 10
data.border = 1
data.sfColor = 0x000000
data.selColor = 0xFFFFFF
data.fontColor = 0x000000
data.color = 0xCCCCCC
data.W = 72
function data:setTextHex(bytes)
  self:clear()
  for i = 1, #bytes, 8 do
    local sub = bytes:sub(i, i + 7)
    self:insert(("%-33s"):format(sub:gsub(".", function(c)
      return ("%02X"):format(c:byte()) .. " "
    end):gsub("^............", "%1  ")) .. sub:gsub(".", function(c)
      return "  " .. c
    end):gsub("[^\x20-\x7e]", "᛫"):gsub("^............", "%1  "), nil)
  end
  elements.msgInfo:redraw()
end
elements.data = data

local chunkList = msgInfo:addList(75, 1, function()
  local self = elements.chunkList
  elements.data:setTextHex(self.items[self.index])
  elements.msgInfo:redraw()
end)
chunkList.sfColor = 0
chunkList.H = 14
chunkList.selColor = 0xFFFFFF
chunkList.fontColor = 0x000000
chunkList.border = 1
chunkList.color = 0xCCCCCC
chunkList.W = 5
elements.chunkList = chunkList

local chunkCount = msgInfo:addLabel(76, 15, "  0")
chunkCount.fontColor = 0x000000
chunkCount.color = 0xCCCCCC
chunkCount.W = 5
elements.chunkCount = chunkCount

local function modemListener(name, recv, send, port, dist, ...)
  elements.msgList:insert(
    ("[" .. ("%10.2f"):format(comp.uptime()) .. "] #" .. ("%5d"):format(port) ..
    " " .. send:sub(1, 8) .. "… → " .. recv:sub(1, 8) .. "…"),
     {comp.uptime(), recv, send, port, dist, ...})
  update()
end

local quitListener = main:addEvent("interrupted", function()
  forms.stop()
end)

event.listen("modem_message", modemListener)

local invoke = com.invoke
com.invoke = function(address, method, ...)
  local comType = com.type(address)
  if method == "send" and comType == "modem" then
    local result = {invoke(address, "send", ...)}
    local modem = com.proxy(address)
    local args = {...}
    local addr = table.remove(args, 1)
    local port = table.remove(args, 1)
    local distance = 0
    if modem.isWireless() then
      distance = modem.getStrength()
    end
    elements.msgList:insert(
      ("[" .. ("%10.2f"):format(comp.uptime()) .. "] #" .. ("%5d"):format(port) ..
      " " .. modem.address:sub(1, 8) .. "… → " .. addr:sub(1, 8) .. "…"),
      {comp.uptime(), addr, modem.address, port, distance, table.unpack(args)})
      update()
    return table.unpack(result)
  elseif method == "send" and comType == "tunnel" then
    local result = {invoke(address, "send", ...)}
    elements.msgList:insert(
      ("[" .. ("%10.2f"):format(comp.uptime()) .. "] #" .. ("%5d"):format(0) ..
      " " .. address:sub(1, 8) .. "… → " .. "LINKED"),
      {comp.uptime(), "LINKED", address, 0, 0, ...})
      update()
  elseif method == "broadcast" and comType == "modem" then
    local result = {invoke(address, "broadcast", ...)}
    local modem = com.proxy(address)
    local args = {...}
    local port = table.remove(args, 1)
    local distance = modem.isWireless() and modem.getStrength() or 0
    elements.msgList:insert(
      ("[" .. ("%10.2f"):format(comp.uptime()) .. "] #" .. ("%5d"):format(port) ..
      " " .. modem.address:sub(1, 8) .. "… → BROADCAST"),
      {comp.uptime(), "BROADCAST", modem.address, port, distance, table.unpack(args)})
      update()
    return table.unpack(result)
  end
  return invoke(address, method, ...)
end

forms.run(main)

com.invoke = invoke

event.ignore("modem_message", modemListener)
gpu.setResolution(oldW, oldH)
gpu.setForeground(oldFG)
gpu.setBackground(oldBG)
os.sleep(0)
term.clear()

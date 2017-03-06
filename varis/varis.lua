local com = require("component")
local fs = require("filesystem")
local term = require("term")
local unicode = require("unicode")

local srl = require("serialization").serialize
local unsrl = require("serialization").unserialize

local forms = require("forms")

local gpu = com.gpu
local screen = com.screen

local cardTypes = {
  {name = "Redstone control",
   options = function(frame, old)
     local addr = frame:addList(2, 2, function() end)
     addr.W = math.floor(frame.W / 2) - 2
     addr.H = frame.H - 2
     addr.border = 0
     addr.color = 0x696969
     addr.fontColor = 0xD2D2D2
     addr.selColor = 0x878787
     addr.sfColor = 0xFFFFFF
     for a in com.list("redstone") do
       table.insert(addr.items, a)
       table.insert(addr.lines, a)
       if old and old.addr == a then
         addr.index = #addr.items
       end
     end

     local side = frame:addList(math.floor(frame.W / 2) + 1, 2, function() end)
     side.W = math.floor(frame.W / 2) - 1
     side.H = frame.H - 2
     side.border = 0
     side.color = 0x696969
     side.fontColor = 0xD2D2D2
     side.selColor = 0x878787
     side.sfColor = 0xFFFFFF
     side.items = {0, 1, 2, 3, 4, 5}
     side.lines = {
       "bottom",
       "top",
       "back/north",
       "front/south",
       "right/west",
       "left/east"
     }
     if old and old.side then
       side.index = old.side
     end

     return {
       addr = addr,
       side = side
     }
   end,
   constructCardHandler = function(addr, side)
     return {
       func = function(self, card)
         if not com.type(addr) then
           local label = card:addLabel(2, 2, "Error: component is no longer available")
           label.fontColor = 0xFF2400
           label.color = card.color
           return
         end
         local input = card:addLabel(2, 2, "Input: " .. ("%d"):format(com.invoke(addr, "getInput", side)))
         input.color = card.color
         input.fontColor = card.fontColor
         local outLabel = card:addLabel(14, 2, "Output: ")
         outLabel.color = card.color
         outLabel.fontColor = card.fontColor
         local output = card:addEdit(22, 1, function(self)
           if com.type(addr) and tonumber(self.text) then
             com.invoke(addr, "setOutput", side, tonumber(self.text))
           end
         end)
         output.text = ("%d"):format(com.invoke(addr, "getOutput", side))
         output.W = 5
         output.H = 3
         output.border = 1
         output.color = card.color
         output.fontColor = card.fontColor

         card:addTimer(1, function(self)
           if com.type(addr) then
             input.caption = "Input: " .. ("%d"):format(com.invoke(addr, "getInput", side))
             input:redraw()
           end
         end)
       end,
       addr = addr,
       side = side
     }
   end,
   func = function(self, frame, state)
     if state.addr.index == 0 then
       return
     end
     if not com.type(state.addr.items[state.addr.index]) then
       return
     end
     if state.side.index == 0 then
       return
     end
     local addr = state.addr.items[state.addr.index]
     local side = state.side.items[state.side.index]
     return self.constructCardHandler(addr, side)
   end,
   save = function(handler)
     return {addr = handler.addr, side = handler.side}
   end,
   load = function(self, data)
     return self.constructCardHandler(data.addr, data.side)
   end}
}

local main = forms.addForm()

local edit = forms.addForm()
edit.color = 0x696969
edit.fontColor = 0xFFFFFF

local addCard = forms.addForm()
addCard.color = 0x4B4B4B
addCard.fontColor = 0xFFFFFF
addCard.editing = false

local content = main:addFrame(1, 1, 0)
content.W = main.W - 1
content.H = main.H
content.color = 0xA5A5A5
content.fontColor = 0x000000
content.scrollOffset = 0
content.contentHeight = 0
content.cards = {}

local scrollBar = main:addFrame(main.W, 1, 0)
scrollBar.W = 1
scrollBar.H = main.H
scrollBar.color = 0x878787
scrollBar.fontColor = 0xFFFFFF

function scrollBar:paint()
  if content.contentHeight == 0 then
    return
  end
  local charsV = {"▂", "▄", "▆", "█"}
  local h = math.floor(content.H / content.contentHeight * scrollBar.H * 4)
  if h < 1 then
    h = 1
  end
  local top = math.ceil(content.scrollOffset / content.contentHeight * scrollBar.H * 4)
  local upperChar
  if top % 4 == 0 then
    upperChar = 0
  else
    upperChar = 4 - (top % 4)
  end
  local blocks = math.floor((h - upperChar) / 4)
  local lowerChar
  if (h - upperChar - blocks * 4) % 4 == 0 then
    lowerChar = 0
  else
    lowerChar = 4 - ((h - upperChar - blocks * 4) % 4)
  end
  local chars = ""
  chars = (" "):rep(math.floor(top / 4))
  if upperChar ~= 0 then
    chars = chars .. charsV[upperChar]
  end
  chars = chars .. charsV[4]:rep(blocks)
  gpu.set(self.X, self.Y, chars, true)
  if lowerChar ~= 0 then
    gpu.setForeground(self.color)
    gpu.setBackground(self.fontColor)
    gpu.set(self.X, self.Y + unicode.len(chars), charsV[lowerChar])
  end
end

function scrollBar:touch(x, y)
  local offset = math.ceil((y - 1) / (self.H - 1) * content.contentHeight)
  content:shift(offset)
end

scrollBar.drag = scrollBar.touch
scrollBar.drop = scrollBar.touch

function content:shift(offset)
  if offset == self.scrollOffset then
    return
  end
  if self.contentHeight - offset < self.H then
    offset = self.contentHeight - self.H
  end
  if offset < 0 then
    offset = 0
  end

  for k, v in pairs(self.elements or {}) do
    v.top = v.top - offset + self.scrollOffset
  end

  self.scrollOffset = offset
  self:redraw()
  scrollBar:redraw()
end

function content:update()
  for i = #(self.elements or {}), 1, -1 do
    self.elements[i]:destruct()
  end

  local height = 1
  for i = 1, #self.cards + 1, 1 do
    local topOffset = 1
    if self.cards[i] then
      local title = self:addFrame(2, height + 1, 0)
      title.W = self.W - 2
      title.H = 1
      title.color = 0xFFFFFF
      title.fontColor = 0x878787
      local titleLabel = title:addLabel(1, 1, cardTypes[self.cards[i].handler].name .. " [" .. self.cards[i].name .. "]")
      titleLabel.W = title.W - 2
      titleLabel.alignRight = true
      titleLabel.autoSize = false
      titleLabel.color = title.color
      titleLabel.fontColor = title.fontColor
      self.cards[i].title = title
      topOffset = 2
    end
    local card = self:addFrame(2, height + topOffset, 0)
    card.W = self.W - 2
    card.H = 3
    card.color = 0xFFFFFF
    card.fontColor = 0x000000
    if self.cards[i] then
      self.cards[i].func(self.cards[i], card)
      self.cards[i].card = card
    else
      self:newCard(card)
    end
    card.top = height + topOffset
    card.scroll = self.scroll
    height = height + card.H + topOffset
  end
  self.contentHeight = height
  self:shift(self.scrollOffset)
end

function content:scroll(_, _, delta)
  content:shift(content.scrollOffset - delta)
end

function content:newCard(card)
  card.color = 0x5A5A5A
  card.fontColor = 0xFFFFFF
  local button = card:addButton(1, 1, "Edit...", function()
    edit:setActive()
  end)
  button.W = card.W
  button.H = card.H
  button.color = card.color
  button.fontColor = card.fontColor
end

local topBar = edit:addFrame(1, 1, 0)
topBar.W = edit.W
topBar.H = 1
topBar.color = 0x3C3C3C
topBar.fontColor = 0xFFFFFF

local editTitle = topBar:addLabel(2, 1, "Edit cards")
editTitle.color = topBar.color
editTitle.fontColor = topBar.fontColor

local editReturn = topBar:addButton(topBar.W - 3 + 1, 1, "×", function()
  main:setActive()
  content:update()
  content:redraw()
end)
editReturn.W = 3
editReturn.H = 1
editReturn.color = 0x660000
editReturn.fontColor = 0xFFFFFF

local cardList = edit:addList(2, 3, function() end)
cardList.W = edit.W - 13 - 3
cardList.H = edit.H - 3
cardList.color = 0x878787
cardList.fontColor = 0xE1E1E1
cardList.selColor = 0xA5A5A5
cardList.sfColor = 0xFFFFFF
cardList.border = 0
function cardList:updateList()
  self.items = {}
  self.lines = {}
  for i = 1, #content.cards, 1 do
    local card = content.cards[i]
    table.insert(self.items, card)
    table.insert(self.lines, card.name)
  end
end

local cardUp = edit:addButton(edit.W - 13, 3, "▲", function()
  if cardList.index > 1 then
    local i = cardList.index
    content.cards[i - 1], content.cards[i] = content.cards[i], content.cards[i - 1]
    cardList.index = i - 1
    cardList:updateList()
    cardList:redraw()
  end
end)
cardUp.W = 5
cardUp.H = 1
cardUp.color = 0x878787
cardUp.fontColor = 0xFFFFFF

local cardDown = edit:addButton(edit.W - 13 + 5 + 3, 3, "▼", function()
  if cardList.index ~= 0 and #cardList.items > 1 and cardList.index ~= #cardList.items then
    local i = cardList.index
    content.cards[i + 1], content.cards[i] = content.cards[i], content.cards[i + 1]
    cardList.index = i + 1
    cardList:updateList()
    cardList:redraw()
  end
end)
cardDown.W = 5
cardDown.H = 1
cardDown.color = 0x878787
cardDown.fontColor = 0xFFFFFF

local cardAdd = edit:addButton(edit.W - 13, 5, "Add card   ", function() end)
cardAdd.W = 13
cardAdd.H = 1
cardAdd.color = 0x878787
cardAdd.fontColor = 0xFFFFFF

local cardEdit = edit:addButton(edit.W - 13, 7, "Edit card  ", function() end)
cardEdit.W = 13
cardEdit.H = 1
cardEdit.color = 0x878787
cardEdit.fontColor = 0xFFFFFF

local cardDelete = edit:addButton(edit.W - 13, 9, "Delete card", function()
  if cardList.index ~= 0 then
    local i = cardList.index
    table.remove(content.cards, i)
    cardList:updateList()
    cardList.index = 0
    cardList:redraw()
  end
end)
cardDelete.W = 13
cardDelete.H = 1
cardDelete.color = 0x878787
cardDelete.fontColor = 0xFFFFFF

local addBar = addCard:addFrame(1, 1, 0)
addBar.W = addCard.W
addBar.H = 1
addBar.color = 0x1E1E1E
addBar.fontColor = 0xFFFFFF

local addBarLabel = addBar:addLabel(2, 1, "Add card")
addBarLabel.color = addBar.color
addBarLabel.fontColor = addBar.fontColor

local addExit = addCard:addButton(addCard.W - 3 + 1, 1, "×", function()
  edit:setActive()
end)
addExit.W = 3
addExit.H = 1
addExit.color = 0x660000
addExit.fontColor = 0xFFFFFF

local addNameLabel = addCard:addLabel(2, 3, "Card name")
addNameLabel.color = addCard.color
addNameLabel.fontColor = addCard.fontColor

local addName = addCard:addEdit(2, 4, function() end)
addName.W = addCard.W - 2
addName.H = 3
addName.color = addCard.color
addName.fontColor = addCard.fontColor

local addTypes = addCard:addList(2, 8)
addTypes.W = addCard.W - 2
addTypes.H = 4
addTypes.border = 0
addTypes.color = 0x696969
addTypes.fontColor = 0xD2D2D2
addTypes.selColor = 0x878787
addTypes.sfColor = 0xFFFFFF
for i = 1, #cardTypes, 1 do
  local v = cardTypes[i]
  table.insert(addTypes.items, v)
  table.insert(addTypes.lines, v.name)
end

local addOptions = addCard:addFrame(2, 13, 1)
addOptions.W = addCard.W - 2
addOptions.H = addCard.H - 15
addOptions.color = addCard.color
addOptions.fontColor = addCard.fontColor

addTypes.onChange = function(self)
  for i = #(addOptions.elements or {}), 1, -1 do
    addOptions.elements[i]:destruct()
  end
  self.state = self.items[self.index].options(addOptions)
  addOptions:redraw()
end

local addCancel = addCard:addButton(2, addCard.H - 1, "Cancel", function()
  edit:setActive()
end)
addCancel.W = math.floor(addCard.W / 2) - 2
addCancel.H = 1
addCancel.color = 0x660000
addCancel.fontColor = 0xFFFFFF

local addSave = addCard:addButton(math.floor(addCard.W / 2) + 1, addCard.H - 1, "Save", function()
  if #addName.text == 0 then
    addName.fontColor = 0x660000
    addName:redraw()
    os.sleep(0.5)
    addName.fontColor = addCard.fontColor
    addName:redraw()
    return
  end
  if addTypes.index == 0 then
    addTypes.color = 0x660000
    addTypes:redraw()
    os.sleep(0.5)
    addTypes.color = 0x696969
    addTypes:redraw()
    return
  end
  local result = addTypes.items[addTypes.index]:func(addOptions, addTypes.state)
  if type(result) == "table" then
    result.name = addName.text
    result.handler = addTypes.index
    if addCard.editing then
      content.cards[addCard.editing] = result
    else
      table.insert(content.cards, result)
    end
    cardList:updateList()
    edit:setActive()
  else
    addOptions.fontColor = 0x660000
    addOptions:redraw()
    os.sleep(0.5)
    addOptions.fontColor = addCard.fontColor
    addOptions:redraw()
  end
end)
addSave.W = math.floor(addCard.W / 2) - 1
addSave.H = 1
addSave.color = 0x696969
addSave.fontColor = 0xFFFFFF

cardAdd.onClick = function()
  addName.text = ""
  addTypes.index = 0
  for i = #(addOptions.elements or {}), 1, -1 do
    addOptions.elements[i]:destruct()
  end
  addCard.editing = false
  addCard:setActive()
end

cardEdit.onClick = function()
  local i = cardList.index
  if i ~= 0 then
    local v = content.cards[i]
    addName.text = v.name
    addTypes.index = v.handler
    for i = #(addOptions.elements or {}), 1, -1 do
      addOptions.elements[i]:destruct()
    end
    addTypes.state = cardTypes[v.handler].options(addOptions, v)
    addCard.editing = i
    addCard:setActive()
  end
end

do
  local oldDestruct = getmetatable(getmetatable(content)).destruct
  getmetatable(getmetatable(content)).destruct = function(self)
    oldDestruct(self)
    for i = #(self.elements or {}), 1, -1 do
      self.elements[i]:destruct()
    end
  end
  local timer = main:addTimer(1,function() end)
  timer:stop()
  getmetatable(timer).destruct = function(self)
    self:stop()
  end
end


do
  if fs.exists("/etc/varis.cfg") then
    local f = io.open("/etc/varis.cfg", "r")
    local all = f:read("*a")
    f:close()
    local cfg = unsrl(all)
    for i = 1, #cfg, 1 do
      local v = cfg[i]
      local card = cardTypes[v[1]]:load(v[2])
      card.name = v[3]
      card.handler = v[1]
      table.insert(content.cards, card)
    end
  end
end

cardList:updateList()
content:update()

scrollBar.scroll = content.scroll

main:addEvent("interrupted", function()
  forms.stop()
end)

local function saveConfig()
  local data = {}
  for i = 1, #content.cards, 1 do
    local card = content.cards[i]
    local v = {card.handler, cardTypes[card.handler].save(card), card.name}
    table.insert(data, v)
  end
  local content = srl(data)
  local f = io.open("/etc/varis.cfg", "w")
  f:write(content)
  f:close()
end

main:addTimer(30, saveConfig)

forms.run(main)

saveConfig()

os.sleep(0)
term.clear()

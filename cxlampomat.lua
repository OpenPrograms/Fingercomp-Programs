local global_lamps = {"cf0", "95c", "ad9", "a1a", "d97", "afb", "cc5", "335", "a75"}
local global_exit = false
local com = require("component")
local event = require("event")
 
local base = {__index = base}
function base.__call(self, count)
  if not global_exit then
    count = count or math.huge
    self.init()
    if not self.customSet then
      self.getLamps(self)
      local lamps = self.lamps
      local r = self.r
      local g = self.g
      local b = self.b
      local formula = self.formula
      local noExit = true
      local cycle = 1
      while noExit and cycle <= count and not global_exit do
        for num, i in ipairs(lamps) do
          pcall(com.invoke, i, "setLampColor", formula(r(), g(), b()))
          if event.pull(0.6, "key_down") then
            noExit = false
            global_exit = true
          end
        end
        cycle = cycle + 1
      end
    else
      self.customSet(self, count)
    end
    for i in com.list("colorful_lamp") do
      com.invoke(i, "setLampColor", 0)
    end
    self.destruct()
  end
end
 
--- WAVE ---
 
wave = setmetatable({}, base)
function wave:getLamps()
  local lampOrder = global_lamps
  local lamps = {}
  for i = 1, #lampOrder, 1 do
    if com.get(lampOrder[i]) then
      table.insert(lamps, com.get(lampOrder[i]))
    end
  end
  wave.lamps = lamps
end
wave.r = function() return math.random(0, 16) end
wave.g = function() return math.random(16, 31) end
wave.b = function() return math.random(0, 16) end
wave.formula = function(r, g, b)
  return r * 32 * 32 + g * 32 + b
end
function wave.added(_, addr, name)
  if name == "colorful_lamp" then
    table.insert(wave.lamps, addr)
  end
end
function wave.removed(_, addr, name)
  if name == "colorful_lamp" then
    table.remove(wave.lamps, addr)
  end
end
function wave.init()
  event.listen("component_added", wave.added)
  event.listen("component_removed", wave.removed)
end
function wave.destruct()
  event.ignore("component_added", wave.added)
  event.ignore("component_removed", wave.removed)
end
 
--- SMOOTH WAVE ---
 
smwv = setmetatable({}, base)
smwv.r = function() return math.random(16, 31) end
smwv.g = function() return math.random(16, 31) end
smwv.b = function() return math.random(16, 31) end
function smwv.onKeyDown()
  smwv.noExit = false
  global_exit = true
  print("Please wait until cycle ends...")
end
function smwv.added(_, addr, name)
  if name == "colorful_lamp" then
    table.insert(smwv.lamps, {addr, 0})
    pcall(com.invoke, addr, "setLampColor", 0)
    print("New lamp available lamp, adding: " .. addr)
  end
end
function smwv.removed(_, addr, name)
  if name == "colorful_lamp" then
    for i = 1, #smwv.lamps, 1 do
      if addr == smwv.lamps[i][1] then
        table.remove(smwv.lamps, i)
        print("Lamp is unavailable, removing: " .. addr)
      end
    end
  end
end
function smwv.init()
  smwv.noExit = true
  event.listen("key_down", smwv.onKeyDown)
  event.listen("component_added", smwv.added)
  event.listen("component_removed", smwv.removed)
end
function smwv.destruct()
  event.ignore("key_down", smwv.onKeyDown)
  event.ignore("component_added", smwv.added)
  event.ignore("component_removed", smwv.removed)
end
function smwv:set()
  for i = 1, #self.lamps, 1 do
    pcall(com.invoke, self.lamps[i][1], "setLampColor", self.lamps[i][2])
  end
end
function smwv:customSet(count)
  local lamps = global_lamps
  self.lamps = {}
  for _, i in ipairs(lamps) do
    if ({pcall(com.get, i)})[1] then
      table.insert(self.lamps, {com.get(i), 0})
    end
  end
  local cycle = 1
  while smwv.noExit and cycle <= count do
    local color = self.r() * 32 * 32 + self.g() * 32 + self.b()
    for i = 1, #self.lamps, 1 do
      if self.lamps[i] then
        self.lamps[i][2] = color
        if i > 1 then
          for j = 1, #self.lamps, 1 do
            if self.lamps[j] and j ~= i then
              local prevcolor = self.lamps[j][2] or 0
              local pr = math.floor(prevcolor / 32 / 32)
              local pg = math.floor((prevcolor - pr * 32 * 32) / 32)
              local pb = prevcolor - pr * 32 * 32 - pg * 32
              local mlpr = ((#self.lamps - 1) / (#self.lamps))
              local newcolor = math.floor(pr * mlpr) * 32 * 32 + math.floor(pg * mlpr) * 32 + math.floor(pb * mlpr)
              self.lamps[j][2] = self.lamps[j] and math.floor(newcolor) or nil
            end
          end
        end
        self:set()
        os.sleep(0.1)
      end
    end
    cycle = cycle + 1
  end
end
 
--- GROUP BLINK ---
 
blink = setmetatable({}, base)
blink.r = function() return math.random(0, 31) end
blink.g = function() return math.random(0, 31) end
blink.b = function() return math.random(0, 31) end
blink.r1 = function() return math.random(0, 31) end
blink.g1 = function() return math.random(0, 31) end
blink.b1 = function() return math.random(0, 31) end
function blink.added(_, addr, name)
  if name == "colorful_lamp" then
    if blink.next then
      table.insert(blink.even, addr)
    else
      table.insert(blink.odd, addr)
    end
    blink.lamps[addr] = blink.next
    print("New lamp available: " .. addr .. ", " .. (blink.next and "even" or "odd"))
    blink.next = not blink.next
  end
end
function blink.removed(_, addr, name)
  if name == "colorful_lamp" then
    if blink.lamps[addr] == true then
      table.remove(blink.even, addr)
    else
      table.remove(blink.odd, addr)
    end
    blink.lamps[addr] = nil
  end
end
function blink.onKeyDown()
  blink.noExit = false
  global_exit = true
  print("Please wait until cycle ends...")
end
function blink.init()
  event.listen("component_added", blink.added)
  event.listen("component_removed", blink.removed)
  event.listen("key_down", blink.onKeyDown)
end
function blink.destruct()
  event.ignore("component_added", blink.added)
  event.ignore("component_removed", blink.removed)
  event.ignore("key_down", blink.onKeyDown)
end
function blink:set(cur, color)
  local lamps = {}
  if cur then
    lamps = self.even
  else
    lamps = self.odd
  end
  for _, i in ipairs(lamps) do
    pcall(com.invoke, i, "setLampColor", color)
  end
end
function blink.clear()
  for i in com.list("colorful_lamp") do
    pcall(com.invoke, i, "setLampColor", 0)
  end
end
function blink:customSet(count)
  local cycle = 1
  self.noExit = true
  local lamps = global_lamps
  self.odd = {}
  self.even = {}
  self.lamps = {}
  self.next = false
  for _, i in ipairs(lamps) do
    if com.get(i) then
      if self.next then
        table.insert(self.even, com.get(i))
      else
        table.insert(self.odd, com.get(i))
      end
      self.lamps[com.get(i)] = self.next
      self.next = not self.next
    end
  end
  while self.noExit and cycle <= count do
    self.color1 = self.r() * 32 * 32 + self.g() * 32 + self.b()
    self.color2 = self.r1() * 32 * 32 + self.g1() * 32 + self.b1()
    self:set(false, self.color1)
    self:set(true, self.color2)
    os.sleep(0.4)
    self.clear()
    os.sleep(0.4)
    cycle = cycle + 1
  end
end
 
--- RANDOM ---
 
rand = setmetatable({}, base)
function rand:getLamps()
  self.lamps = {}
  for i in com.list("colorful_lamp") do
    table.insert(self.lamps, i)
  end
end
rand.r = function() return math.random(0, 31) end
rand.g = function() return math.random(0, 31) end
rand.b = function() return math.random(0, 31) end
rand.formula = function(r, g, b) return r * 32 * 32 + g * 32 + b end
function rand.init() end
function rand.destruct() end
 
--- BIGLAMP ---
 
big = setmetatable({}, base)
big.r = function() return math.random(0, 31) end
big.g = function() return math.random(0, 31) end
big.b = function() return math.random(0, 31) end
function big.onKeyDown()
  big.noExit = false
  global_exit = true
  print("Please wait until cycle ends...")
end
function big.init()
  event.listen("key_down", big.onKeyDown)
end
function big.destruct()
  event.ignore("key_down", big.onKeyDown)
end
function big:customSet(count)
  self.noExit = true
  local cycle = 0
  local color = {0, 0, 0}
  local mlpr = 8/9
  while self.noExit and cycle <= count do
    color = {math.floor(color[1] * mlpr), math.floor(color[2] * mlpr), math.floor(color[3] * mlpr)}
    if color[1] < 1 and color[2] < 1 and color[3] < 1 then
      color = {self.r(), self.g(), self.b()}
      cycle = cycle + 1
      os.sleep(0.8)
      if cycle > count then break end
    end
    for i in com.list("colorful_lamp") do
      pcall(com.invoke, i, "setLampColor", color[1] * 32 * 32 + color[2] * 32 + color[3])
    end
    os.sleep(0.3)
  end
end
 
 
--- MAIN ---
 
while not global_exit do
  big(5)
  rand(2)
  wave(5)
  smwv(20)
  blink(5)
end

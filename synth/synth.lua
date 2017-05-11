-- Copyright 2017 Fingercomp, LeshaInc

-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at

--     http://www.apache.org/licenses/LICENSE-2.0

-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

local bit32 = require("bit32")
local com = require("component")
local event = require("event")
local kbd = require("keyboard")
local unicode = require("unicode")

local buf = require("synth.doubleBuffering")
local gui = require("synth.GUI")

local gpu = com.gpu
local sound = com.sound

local w, h = gpu.getViewport()

local sampleRate = 44100

buf.start()
buf.clear(0x0049C0)
buf.draw(true)

local objects = {}
local pins = {}
local selected = false
local config = false
local cardAdd = false

local side = {
  top = 1,
  bottom = 0,
  left = 2,
  right = 3,
  {0, -1},
  {0, 1},
  {-1, 0},
  {1, 0}
}

local cardADSR, cardFM, cardPlot, cardWave, cardSoundCard, cardVolume, cardChannel, cardFrequency, cardLFSR

local function isin(value, tbl)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local braille = {
  [0] = {
    [0] = 0x1,
    0x2,
    0x4,
    0x40
  },
  [1] = {
    [0] = 0x8,
    0x10,
    0x20,
    0x80
  }
}
local function line(x0, y0, x1, y1)
  local steep = false
  if math.abs(x0 - x1) < math.abs(y0 - y1) then
    x0, y0 = y0, x0
    x1, y1 = y1, x1
    steep = true
  end
  if x0 > x1 then
    x0, x1 = x1, x0
    y0, y1 = y1, y0
  end
  local dx = x1 - x0
  local dy = y1 - y0
  local derr = math.abs(dy) * 2;
  local err = 0;
  local y = y0
  local points = {}
  for x = x0, x1, 1 do
    if steep then
      table.insert(points, {y, x})
    else
      table.insert(points, {x, y})
    end
    err = err + derr
    if err > dx then
      if y1 > y0 then
        y = y + 1
      else
        y = y - 1
      end
      err = err - dx * 2
    end
  end
  return points
end

local function namedCheckArg(name, value, ...)
  local t = type(value)
  local e
  for _, v in ipairs({...}) do
    if t == v then
      return
    else
      e = ("bad named argument '%s' (%s expected, got %s)"):format(
        name, table.concat({...}, " or "), t)
    end
  end
  error(e, 3)
end

local brailleMap do
  brailleMap = {}
  brailleMap.__index = brailleMap

  local function unit(a, b, c, d, e, f, g, h)
    a = a and 1 or 0
    b = b and 1 or 0
    c = c and 1 or 0
    d = d and 1 or 0
    e = e and 1 or 0
    f = f and 1 or 0
    g = g and 1 or 0
    h = h and 1 or 0
    return unicode.char(
      10240 + 128 * h + 64 * d + 32 * g + 16 * f + 8 * e + 4 * c + 2 * b + a)
  end

  function brailleMap:set(x, y, v)
    v = v and v or 0xFFFFFF
    x = x - 1
    y = y - 1
    if x >= 0 and x < self.width and y >= 0 and y < self.height then
      self.data[self.width * y + x] = v
    end
  end

  function brailleMap:get(x, y)
    x = x - 1
    y = y - 1
    if x >= 0 and x < self.width and y >= 0 and y < self.height then
      return self.data[self.width * y + x] or nil
    else
      return nil
    end
  end

  local function rgb2hex(r, g, b)
    r = math.floor(r + 0.5)
    g = math.floor(g + 0.5)
    b = math.floor(b + 0.5)
    return bit32.rshift(r, 16) + bit32.rshift(g, 8) + b
  end

  local function hex2rgb(hex)
    hex = math.floor(hex + 0.5)
    return bit32.lshift(hex, 16),
      bit32.band(bit32.lshift(hex, 8), 0xFF),
      bit32.band(hex, 0xFF)
  end

  local function sum(a)
    local result = 0
    for _, v in pairs(a) do
      result = result + v
    end
    return result
  end

  local function color8interpolate(a, b, c, d, e, f, g, h)
    local count = 0
    local unique = {}
    local rarr, garr, barr = {}, {}, {}

    for _, v in ipairs({a or 0, b or 0, c or 0, d or 0, e or 0, f or 0, g or 0, h or 0}) do
      if v ~= 0 and not unique[v] then
        unique[v] = true
        rarr[count + 1], garr[count + 1], barr[count + 1] = hex2rgb(v)
        count = count + 1
      end
    end

    local r = sum(rarr) / count
    local g = sum(garr) / count
    local b = sum(barr) / count

    return rgb2hex(r, g, b)
  end

  function brailleMap:draw(x, y, bg)
    local sy = 0
    for dy = 1, self.height, 4 do
      local sx = 0
      for dx = 1, self.width, 2 do
        local a, b, c, d, e, f, g, h =
          self:get(dx, dy), self:get(dx, dy + 1),
          self:get(dx, dy + 2), self:get(dx, dy + 3),
          self:get(dx + 1, dy), self:get(dx + 1, dy + 1),
          self:get(dx + 1, dy + 2), self:get(dx + 1, dy + 3)

        local nfg = a or b or c or d or e or f or g or h or 0xE1E1E1

        if (a and a ~= nfg) or
           (b and b ~= nfg) or
           (c and c ~= nfg) or
           (d and d ~= nfg) or
           (e and e ~= nfg) or
           (f and f ~= nfg) or
           (g and g ~= nfg) or
           (h and h ~= nfg) then
          nfg = color8interpolate(a, b, c, d, e, f, g, h)
        end

        local c = unit(a, b, c, d, e, f, g, h)
        if c ~= "⠀" then
          buf.set(x + sx, y + sy, bg, nfg, c)
        end
        sx = sx + 1
      end
      sy = sy + 1
    end
  end

  setmetatable(brailleMap, {
    __call = function(_, w, h)
      local self = setmetatable({}, brailleMap)
      self.width = w
      self.height = h
      self.data = {}
      return self
    end
  })
end

local plot do
  plot = {}
  plot.__index = plot

  function plot:calculateCenter(vx, vy, vw, vh)
    self.centerY = vy + (vh * math.abs(self.ly)) / (math.abs(self.ly) + self.uy) - 1
    self.centerX = vx + (vw * math.abs(self.lx)) / (math.abs(self.lx) + self.ux) - 1
  end

  function plot:drawXAxis(vx, vy, vw, vh)
    self:calculateCenter(vx, vy, vw, vh)
    buf.square(vx, math.floor(self.centerY + 0.5), vw - 1, 1, self.background, self.axisColor, "─")
    buf.set(vx + vw - 1, math.floor(self.centerY + 0.5), self.background, self.axisColor, "→")
  end

  function plot:drawYAxis(vx, vy, vw, vh)
    self:calculateCenter(vx, vy, vw, vh)
    buf.square(math.floor(self.centerX + 0.5), vy + 1, 1, vh - 1, self.background, self.axisColor, "│")
    buf.set(math.floor(self.centerX + 0.5), vy, self.background, self.axisColor, "↑")
  end

  function plot:drawXYPoint(vx, vy, vw, vh)
    buf.set(math.floor(self.centerX + 0.5), math.floor(self.centerY + 0.5), self.background, self.axisColor, "┼")
  end

  function plot:draw(vx, vy, vw, vh)
    checkArg(1, vx, "number")
    checkArg(2, vy, "number")
    checkArg(3, vw, "number")
    checkArg(4, vh, "number")

    self.lx, self.ux = self.xRange[1], self.xRange[2]
    self.ly, self.uy = self.yRange[1], self.yRange[2]

    buf.square(vx, vy, vw, vh, self.background, self.axisColor, " ")

    vh = vh - self:renderLabels(vx, vy, vw, vh)
    self:calculateCenter(vx, vy, vw, vh)

    if self.isAxisVisible and self.axisPosition == "bottom" then
      self:drawXAxis(vx, vy, vw, vh)
      self:drawYAxis(vx, vy, vw, vh)
      self:drawXYPoint()
    end

    self.braille = brailleMap(vw * 2, vh * 4)

    for _, fun in pairs(self.functions) do
      if not fun.hidden then
        self:plotFunction(vx, vy, vw, vh, fun.fun, fun.color, fun.step)
      end
    end

    self.braille:draw(vx, vy, self.background)
    if self.isAxisVisible and self.axisPosition == "top" then
      self:drawXAxis(vx, vy, vw, vh)
      self:drawYAxis(vx, vy, vw, vh)
      self:drawXYPoint()
    end
  end

  function plot:fun(fun, label, color, step)
    checkArg(1, fun, "function")
    checkArg(2, label, "string", "nil")
    checkArg(3, color, "number", "nil")
    checkArg(4, step, "number", "nil")

    local id = #self.functions + 1

    self.functions[id] = {
      fun = fun,
      color = color or 0xe1e1e1,
      step = step or 0.01,
      label = label,
      hidden = false,

      remove = function()
        self.functions[id] = nil
      end,

      hide = function()
        self.functions[id].hidden = true
      end,

      show = function()
        self.functions[id].hidden = false
      end,
    }

    return self.functions[id]
  end

  function plot:renderLabels(vx, vy, vw, vh)
    local sx = 0

    for _, fun in pairs(self.functions) do
      if not fun.hidden and fun.label then
        buf.square(vx + sx, vy + vh - 1, unicode.len(fun.label), 1, self.background, fun.color, " ")
        buf.text(vx + sx, vy + vh - 1, fun.color, fun.label)
        sx = sx + unicode.len(fun.label) + 2
      end
    end

    local keys = {}
    local n = 0

    for k in pairs(self.labels) do
      n = n + 1
      keys[n] = k
    end

    table.sort(keys)

    for _, k in ipairs(keys) do
      local label = self.labels[k]
      if not label.hidden and #label.text ~= 0 then
        buf.square(vx + sx, vy + vh - 1, unicode.len(label.text), 1, self.background, label.color, " ")
        buf.text(vx + sx, vy + vh - 1, label.color, label.text)
        sx = sx + unicode.len(label.text) + 2
      end
    end

    return sx > 0 and 1 or 0
  end

  function plot:plotFunction(vx, vy, vw, vh, fun, color, step)
    self:calculateCenter(1, 1, vw, vh)
    local rw, rh = self.ux - self.lx,
      self.uy - self.ly

    local mx, my, kx, ky = self.centerX * 2,
      self.centerY * 4, vw * 2 / rw, vh * 4 / rh

    for x = self.lx, self.ux, step do
      local y = fun(x)
      local px = kx * x + mx
      local py = ky * -y + my
      self.braille:set(math.floor(px + 0.5), math.floor(py + 0.5), color)
    end
  end

  function plot:label(text, color)
    local id = #self.labels + 1

    self.labels[id] = {
      text = text,
      color = color or 0xe1e1e1,
      hidden = false,

      remove = function()
        self.labels[id] = nil
      end,

      hide = function()
        self.labels[id].hidden = true
      end,

      show = function()
        self.labels[id].hidden = false
      end
    }

    return self.labels[id]
  end

  setmetatable(plot, {
    __call = function(_, args)
      local self = setmetatable({}, plot)

      checkArg(1, args, "table", "nil")
      args = args or {}

      namedCheckArg("xRange", args.xRange, "table", "nil")
      namedCheckArg("yRange", args.yRange, "table", "nil")

      self.functions = {}
      self.labels = {}

      self.xRange = args.xRange or {-1, 1}
      self.yRange = args.yRange or {-1, 1}

      namedCheckArg("xRange[1]", self.xRange[1], "number")
      namedCheckArg("xRange[2]", self.xRange[2], "number")
      namedCheckArg("yRange[1]", self.yRange[1], "number")
      namedCheckArg("yRange[2]", self.yRange[2], "number")

      assert(self.xRange[1] < self.xRange[2],
        "axis x: the lower bound must be less than the upper")
      assert(self.yRange[1] < self.yRange[2],
        "axis y: the lower bound must be less than the upper")

      namedCheckArg("background", args.background, "number", "nil")
      self.background = args.background or 0x0f0f0f

      namedCheckArg("axisColor", args.axisColor, "number", "nil")
      self.axisColor = args.axisColor or 0x1e1e1e

      namedCheckArg("isAxisVisible", args.isAxisVisible, "boolean", "nil")
      self.isAxisVisible = type(args.isAxisVisible) == "nil" and true
        or args.isAxisVisible

      namedCheckArg("axisPosition", args.axisPosition, "string", "nil")
      if args.axisPosition then
        assert(args.axisPosition == "top" or args.axisPosition == "bottom")
      end
      self.axisPosition = args.axisPosition or "bottom"

      return self
    end
  })
end

local function getPinLineCoords(pin)
  local x = pin.card.x + pin.x
  local y = pin.card.y + pin.y
  x = (x - 1) * 2 + 1
  y = (y - 1) * 4 + 1
  if pin.side == side.left then
    x = x - 1
    y = y + 1 * 4 / 2
  elseif pin.side == side.top then
    x = x + unicode.len(pin.label) * 2 / 2
    y = y - 1
  elseif pin.side == side.right then
    x = x + unicode.len(pin.label) * 2
    y = y + 1 * 4 / 2
  elseif pin.side == side.bottom then
    x = x + unicode.len(pin.label) * 2 / 2
    y = y + 1 * 4
  end
  return x, y
end

local function resetSoundCard()
  sound.setTotalVolume(1)
  for i = 1, 8, 1 do
    sound.close(i)
    sound.resetEnvelope(i)
    sound.resetFM(i)
    sound.resetAM(i)
    sound.setWave(i, sound.modes.sine)
    sound.setFrequency(i, 0)
    sound.setVolume(i, 1)
  end
  sound.process()
  sound.clear()
  sound.process()
end

local function quit(exitCode)
  resetSoundCard()

  buf.clear(0x000000)
  buf.draw()

  gpu.setForeground(0xFFFFFF)
  gpu.setBackground(0x000000)
  os.exit(exitCode)
end


local function redraw()
  buf.clear(0x0049C0)
  local field = {}
  local points = {}
  for _, pin1 in pairs(pins) do
    for k, pin2 in pairs(pin1.connected) do
      local x1, y1 = getPinLineCoords(pin1)
      local x2, y2 = getPinLineCoords(pin2)
      local linePoints = line(x1, y1, x2, y2)
      for _, p in pairs(linePoints) do
        table.insert(points, p)
      end
    end
  end
  for i = 0, #points - 1, 1 do
    local p = points[i + 1]
    local realX = math.ceil(p[1] / 2)
    local realY = math.ceil(p[2] / 4)
    local relX = (p[1] - 1) % 2
    local relY = (p[2] - 1) % 4
    local dot = braille[relX][relY]
    field[realX] = field[realX] or {}
    field[realX][realY] = field[realX][realY] or 0
    field[realX][realY] = bit32.bor(field[realX][realY], dot)
  end
  for x, _ in pairs(field) do
    for y, v in pairs(field[x]) do
      buf.set(x, y, 0x0049C0, 0xD2D2D2, unicode.char(0x2800 + v))
    end
  end
  for i = 1, #objects, 1 do
    objects[i]:draw()
  end
  if selected then
    buf.clear(0x000000, 40)
    for _, pin in pairs(pins) do
      if pin == selected or pin.isInput and pin.type == selected.type and pin.card ~= selected.card then
        pin:draw()
      end
    end
  elseif config then
    buf.clear(0x000000, 40)
    local window = gui.fullScreenWindow()
    function window.onAnyEvent(e)
      if e[1] == "interrupted" then
        window:close()
        quit()
      end
    end
    local container = window:addContainer(math.floor((window.width - 50) / 2), 5, 50, window.height - 4)

    local payloadContainer = container:addContainer(1, 1, 50, 12)

    if config.config then
      config:config(payloadContainer)
    end

    local deleteButton = container:addButton(1, 14, 50, 3, 0xCC0000, 0xFFFFFF, 0xFF0000, 0x000000, "Delete object")
    deleteButton.onTouch = function(self)
      for _, pinTable in pairs({config.inputs, config.outputs}) do
        for _, pin in pairs(pinTable) do
          local toRemove = {}
          for _, other in pairs(pin.connected) do
            table.remove(other.connected, select(2, isin(pin, other.connected)))
          end
          table.remove(pins, select(2, isin(pin, pins)))
        end
      end
      table.remove(objects, select(2, isin(objects, config)))
      config = false
      window:close()
    end

    local closeButton = container:addButton(1, 18, 50, 3, 0xFFFFFF, 0x000000, 0xC3C3C3, 0x3C3C3C, "Close")
    closeButton.onTouch = function(self)
      config = false
      window:close()
    end

    window:draw()
    buf.draw()
    window:handleEvents()
  elseif cardAdd then
    buf.clear(0x000000, 40)
    local window = gui.fullScreenWindow()
    function window.onAnyEvent(e)
      if e[1] == "interrupted" then
        window:close()
        quit()
      end
    end
    local container = window:addContainer(math.floor((window.width - 50) / 2), 5, 50, window.height - 4)

    local payloadContainer = container:addContainer(1, 1, 50, 12)
    local comboBox = payloadContainer:addComboBox(1, 1, payloadContainer.width, 1, 0xFFFFFF, 0x000000, 0xB2B2B2, 0x969696)
    comboBox:addItem("Channel").onTouch = function()
      local channels = {true, true, true, true, true, true, true, true}
      for _, o in pairs(objects) do
        if o.type == "chan" then
          channels[o._chan] = false
        end
      end
      for i = 1, #channels, 1 do
        if channels[i] then
          cardChannel(table.unpack(cardAdd))._chan = i
          break
        end
      end
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Wave").onTouch = function()
      cardWave(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Volume").onTouch = function()
      cardVolume(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Frequency").onTouch = function()
      cardFrequency(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Sound card").onTouch = function()
      for _, o in pairs(objects) do
        if o.type == "sound" then
          return
        end
      end
      cardSoundCard(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Plot").onTouch = function()
      cardPlot(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("ADSR").onTouch = function()
      cardADSR(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("Frequency modulator").onTouch = function()
      cardFM(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end
    comboBox:addItem("LFSR").onTouch = function()
      cardLFSR(table.unpack(cardAdd))
      cardAdd = false
      window:close()
    end

    local closeButton = container:addButton(1, 18, 50, 3, 0xFFFFFF, 0x000000, 0xC3C3C3, 0x3C3C3C, "Close")
    closeButton.onTouch = function(self)
      cardAdd = false
      window:close()
    end

    window:draw()
    buf.draw()
    window:handleEvents()
  end
  buf.draw()
end

local function addCard(x, y, w, h, bx, by, bw, bh, type, paint)
  local o = {
    x = x,
    y = y,
    w = w,
    h = h,
    bx = bx,
    by = by,
    bw = bw,
    bh = bh,
    type = type,
    paint = paint,
    draw = function(self)
      self:paint()
      for _, pin in pairs(self.inputs) do
        pin:draw()
      end
      for _, pin in pairs(self.outputs) do
        pin:draw()
      end
    end,
    inputs = {},
    outputs = {}
  }
  table.insert(objects, o)
  return o
end

local function addPin(card, x, y, fg, bg, label, type, side, single, output)
  local pin = {
    draw = function(self)
      -- get absolute coords
      local ax = card.x + x
      local ay = card.y + y
      buf.square(ax, ay, unicode.len(label), 1, bg, fg, " ")
      buf.text(ax, ay, fg, label)
    end,
    x = x,
    y = y,
    label = label,
    fg = fg,
    bg = bg,
    type = type,
    isInput = not output,
    connected = {},
    card = card,
    side = side,
    single = single
  }
  if not output then
    table.insert(card.inputs, pin)
  else
    table.insert(card.outputs, pin)
  end
  table.insert(pins, pin)
  return pin
end

function cardChannel(x, y)
  local card = addCard(x, y, 17, 3, 0, 0, 16, 3, "chan", function(self)
    buf.square(self.x, self.y, 16, 3, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y + 1, 0x000000, "Channel #" .. self._chan)
  end)
  card._chan = 1
  local adsr = addPin(card, 1, 0, 0xFFFFFF, 0x66DB24, "ADSR", "adsr", side.top, true)
  local freqMod = addPin(card, 6, 0, 0xFFFFFF, 0xCC4900, " FM ", "freqmod", side.top, true)
  local ampMod = addPin(card, 11, 0, 0xFFFFFF, 0x990000, " AM ", "chan", side.top, true)
  local wave = addPin(card, 1, 2, 0x000000, 0xFF00FF, "Wave", "wave", side.bottom, true)
  local volume = addPin(card, 6, 2, 0x000000, 0xFFB600, "Vol ", "volume", side.bottom, true)
  local freq = addPin(card, 11, 2, 0x000000, 0x66DBFF, "Freq", "freq", side.bottom, true)
  addPin(card, 16, 1, 0xFFFFFF, 0x990000, ">", "chan", side.right, false, true)
  function card:update()
    if adsr.connected[1] then
      sound.setADSR(self._chan,
                    adsr.connected[1].card._attack,
                    adsr.connected[1].card._decay,
                    adsr.connected[1].card._sustain,
                    adsr.connected[1].card._release)
    end
    if freqMod.connected[1] then
      freqMod.connected[1].card:update()
      if freqMod.connected[1].card.inputs[1].connected[1] then
        sound.setFM(self._chan,
                    freqMod.connected[1].card.inputs[1].connected[1].card._chan,
                    freqMod.connected[1].card._intensity)
      end
    end
    if ampMod.connected[1] then
      sound.setAM(self._chan, ampMod.connected[1].card._chan)
    end
    if wave.connected[1] then
      if wave.connected[1].card.type == "wave" then
        sound.setWave(self._chan, sound.modes[wave.connected[1].card._wave:lower()])
      elseif wave.connected[1].card.type == "lfsr" then
        sound.setLFSR(self._chan, wave.connected[1].card._value, wave.connected[1].card._mask)
      end
    end
    if volume.connected[1] then
      sound.setVolume(self._chan, volume.connected[1].card._volume)
    end
    if freq.connected[1] then
      sound.setFrequency(self._chan, freq.connected[1].card._frequency)
    end
  end
  return card
end

local waveBraille = {
  Sine     = "⡰⠱⡰⠱⡰⠱⡰⠱",
  Square   = "⣸⠉⣇⣸⠉⣇⣸⠉",
  Triangle = "⡠⠊⠢⡠⠊⠢⡠⠊",
  Sawtooth = "⡠⠊⣇⠔⢹⡠⠊⣇",
  Noise    = "⢂⠌⢁⠢⡐⠌⠡⢂"
}

function cardWave(x, y)
  local card = addCard(x, y, 11, 3, 0, 0, 10, 3, "wave", function(self)
    buf.square(self.x, self.y, 10, 3, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "Wave")
    buf.text(self.x + 1, self.y + 1, 0x696969, waveBraille[self._wave])
    buf.text(self.x + 1, self.y + 2, 0x696969, self._wave)
  end)
  card._wave = "Sine"
  addPin(card, 10, 1, 0x000000, 0xFF00FF, ">", "wave", side.right, false, true)
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Waveform")
    local comboBox = container:addComboBox(1, 2, container.width, 3, 0xFFFFFF, 0x000000, 0x2B2B2B, 0x969696)
    comboBox:addItem("Noise")
    comboBox:addItem("Sine")
    comboBox:addItem("Square")
    comboBox:addItem("Triangle")
    comboBox:addItem("Sawtooth")
    function comboBox.onItemSelected(item)
      self._wave = item.text
    end
  end
  return card
end

local superNum = {
  [0] = "⁰",
  "¹",
  "²",
  "³",
  "⁴",
  "⁵",
  "⁶",
  "⁷",
  "⁸",
  "⁹"
}
function cardVolume(x, y)
  local card = addCard(x, y, 9, 2, 0, 0, 8, 2, "volume", function(self)
    buf.square(self.x, self.y, 8, 2, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "Volume")
    local int, frac = math.modf(self._volume * 100)
    frac = ("%02d"):format(math.floor(frac * 100 + 0.5))
    frac = frac:gsub(".", function(c) return superNum[tonumber(c)] end)
    buf.text(self.x + 1, self.y + 1, 0x696969, ("%3d%s%%"):format(int, frac))
  end)
  card._volume = 0.9999
  addPin(card, 8, 0, 0x000000, 0xFFB600, ">", "volume", side.right, false, true)
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Volume (in percents)")
    local textVolume = container:addInputTextBox(1, 2, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._volume * 100))
    function textVolume.validator(text)
      if text:match("^%d+%.?%d*$") and tonumber(text) <= 100 then
        return true
      end
      return false
    end
    function textVolume.onInputFinished(text)
      self._volume = tonumber(text) and tonumber(text) / 100 or self._volume
    end
  end
  return card
end

function cardFrequency(x, y)
  local card = addCard(x, y, 13, 2, 0, 0, 12, 2, "freq", function(self)
    buf.square(self.x, self.y, 12, 2, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "Frequency")
    local int, frac = math.modf(self._frequency)
    frac = ("%03d"):format(math.floor(frac * 1000 + 0.5))
    frac = frac:gsub(".", function(c) return superNum[tonumber(c)] end)
    buf.text(self.x + 1, self.y + 1, 0x696969, ("%5d%sHz"):format(int, frac))
  end)
  card._frequency = 440
  addPin(card, 12, 0, 0x000000, 0x66DBFF, ">", "freq", side.right, false, true)
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Frequency")
    local textFreq = container:addInputTextBox(1, 2, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(card._frequency))
    function textFreq.validator(text)
      if text:match("^%d+%.?%d*$") and tonumber(text) < 44100 then
        return true
      end
      return false
    end
    function textFreq.onInputFinished(text)
      self._frequency = tonumber(text) or self._frequency
    end
  end
  return card
end

function cardFM(x, y)
  local card = addCard(x, y, 13, 4, 0, 0, 12, 4, "fm", function(self)
    buf.square(self.x, self.y, 12, 4, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y + 1, 0x000000, "Frequency")
    buf.text(self.x + 1, self.y + 2, 0x000000, "modulator")
    local int, frac = math.modf(self._intensity)
    frac = ("%03d"):format(math.floor(frac * 1000 + 0.5))
    frac = frac:gsub(".", function(c) return superNum[tonumber(c)] end)
    buf.text(self.x + 1, self.y + 3, 0x696969, ("I=%5d%s"):format(int, frac))
  end)
  card._intensity = 100
  local chan = addPin(card, 4, 0, 0xFFFFFF, 0x990000, "Chan", "chan", side.top, true)
  addPin(card, 12, 1, 0xFFFFFF, 0xCC4900, ">", "freqmod", side.right, false, true)
  function card:update()
    if chan.connected[1] then
      chan.connected[1].card:update()
    end
  end
  function card:config(container)
    local label = container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Modulator intensity")
    local textIntensity = container:addInputTextBox(1, 2, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._intensity), "Modulator intensity...")
    function textIntensity.validate(text)
      if text:match("^%d+%.?%d*$") and tonumber(text) <= 44100 then
        return true
      end
      return false
    end
    function textIntensity.onInputFinished(text)
      self._intensity = tonumber(text) or 0
    end
  end
  return card
end

function cardSoundCard(x, y)
  local card = addCard(x, y, 17, 5, 0, 0, 17, 5, "sound", function(self)
    buf.square(self.x, self.y, 17, 5, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 4, self.y + 2, 0x000000, "Sound card")
  end)
  addPin(card, 1, 0, 0xFFFFFF, 0x990000, "Ch1", "chan", side.top, true)
  addPin(card, 5, 0, 0xFFFFFF, 0x990000, "Ch2", "chan", side.top, true)
  addPin(card, 9, 0, 0xFFFFFF, 0x990000, "Ch3", "chan", side.top, true)
  addPin(card, 13, 0, 0xFFFFFF, 0x990000, "Ch4", "chan", side.top, true)
  addPin(card, 1, 4, 0xFFFFFF, 0x990000, "Ch5", "chan", side.bottom, true)
  addPin(card, 5, 4, 0xFFFFFF, 0x990000, "Ch6", "chan", side.bottom, true)
  addPin(card, 9, 4, 0xFFFFFF, 0x990000, "Ch7", "chan", side.bottom, true)
  addPin(card, 13, 4, 0xFFFFFF, 0x990000, "Ch8", "chan", side.bottom, true)
  addPin(card, 0, 2, 0x000000, 0xFFB600, "Vol", "volume", side.left, true)
  function card:update()
    sound.setTotalVolume(1)
    for _, pin in pairs(self.inputs) do
      if pin.type == "volume" then
        if pin.connected[1] then
          sound.setTotalVolume(pin.connected[1].card._volume)
        end
      elseif pin.type == "chan" then
        if pin.connected[1] then
          sound.open(pin.connected[1].card._chan)
          pin.connected[1].card:update()
        end
      end
    end
    sound.delay(100)
  end
  return card
end

local generators
generators = {
  noise = {
    type = "noise",
    output = nil,
    generate = function(self)
      if not self.output then
        self:update()
      end
      return self.output
    end,
    update = function(self, offset)
      self.output = math.random(-1000000, 1000000) / 1000000
    end
  },
  square = {
    type = "square",
    generate = function(self, offset)
      local v = generators.sine.generate(offset)
      if v > 0 then
        v = 1
      elseif v < 0 then
        v = -1
      end
      return v / 2
    end
  },
  sine = {
    type = "sine",
    generate = function(self, offset)
      return math.sin(2 * math.pi * offset)
    end
  },
  triangle = {
    type = "triangle",
    generate = function(self, offset)
      return 1 - math.abs(offset - 0.5) * 4
    end
  },
  sawtooth = {
    type = "sawtooth",
    generate = function(self, offset)
      return 2 * offset - 1
    end
  },
  lfsr = function(value, mask)
    return {
      type = "lfsr",
      output = nil,
      generate = function(self)
        if not self.output then
          self:update()
        end
        return self.output
      end,
      update = function(self)
        if bit32.band(value, 1) ~= 0 then
          value = bit32.bxor(bit32.rshift(value, 1), mask)
          self.output = 1
        else
          value = bit32.rshift(value, 1)
          self.output = -1
        end
      end
    }
  end
}

local function modulateFrequency(channels, chan, modulator, value)
  local modChan = channels[modulator.chan]
  if not modChan then
    return value
  end
  local deviation = modChan:getValue(channels, true) * modulator.index
  chan.offset = chan.offset + (chan.freq + deviation) / sampleRate
  return value
end

local function modulateAmplitude(channels, chan, modulator, value)
  -- error(tostring(modulator) .. tostring(value) .. tostring(channels[modulator]))
  local modChan = channels[modulator]
  if not modChan then
    return value
  end
  return value * (1 + modChan:getValue(channels, true))
end

local function loadChannelConfiguration(chan)
  local generator = generators.sine
  local index = chan._chan
  local freq = 0
  local offset = 0
  local freqMod
  local ampMod
  local adsr
  local volume = 1
  local isFreqMod = false
  local isAmpMod = false
  for _, pin in pairs(chan.inputs) do
    if pin.connected[1] then
      if pin.type == "wave" then
        if pin.connected[1].card.type == "wave" then
          generator = generators[pin.connected[1].card._wave:lower()]
        elseif pin.connected[1].card.type == "lfsr" then
          generator = generators.lfsr(pin.connected[1].card._value, pin.connected[1].card._mask)
        end
      elseif pin.type == "freq" then
        freq = pin.connected[1].card._frequency
      elseif pin.type == "freqmod" then
        if pin.connected[1].card.inputs[1].connected[1] then
          freqMod = {
            chan = pin.connected[1].card.inputs[1].connected[1].card._chan,
            index = pin.connected[1].card._intensity
          }
        end
      elseif pin.type == "chan" then
        ampMod = pin.connected[1].card._chan
      elseif pin.type == "adsr" then
        local card = pin.connected[1].card
        adsr = {
          attack = card._attack,
          decay = card._decay,
          sustain = card._sustain,
          release = card._release
        }
      elseif pin.type == "volume" then
        volume = pin.connected[1].card._volume
      end
    end
  end
  for _, pin in pairs(chan.outputs[1].connected) do
    if pin.card.type == "fm" then  -- FM
      if pin.card.outputs[1].connected[1] then
        isFreqMod = pin.card.outputs[1].connected[1].card._chan
      end
    elseif pin.card.type == "chan" then  -- AM
      isAmpMod = pin.card._chan
    end
  end
  return {
    generator = generator,
    index = index,
    freq = freq,
    offset = offset,
    freqMod = freqMod,
    ampMod = ampMod,
    adsr = adsr,
    volume = volume,
    isFreqMod = isFreqMod,
    isAmpMod = isAmpMod,
    getValue = function(self, channels, isModulating)
      -- Copy the modulator settings to avoid changes to the channels table
      local isFreqMod, isAmpMod, freqMod, ampMod = self.isFreqMod, self.isAmpMod, self.freqMod, self.ampMod
      -- We want to ignore modulator that isn't connected to the plot,
      -- just as the sound card does.
      if isFreqMod and not channels[isFreqMod] then
        isFreqMod = nil
      end
      if isAmpMod and not channels[isAmpMod] then
        isAmpMod = nil
      end
      if freqMod and not channels[freqMod.chan] then
        freqMod = nil
      end
      if ampMod and not channels[ampMod] then
        ampMod = nil
      end

      if not isModulating and (isFreqMod or isAmpMod) then
        return 0
      end
      local value = self.generator:generate(self.offset)
      if freqMod and not isFreqMod and not isAmpMod then
        value = modulateFrequency(channels, self, freqMod, value)
      else
        self.offset = self.offset + self.freq / sampleRate
      end
      if self.offset > 1 then
        self.offset = self.offset % 1
        if self.generator.update then
          self.generator:update(self.offset)
        end
      end
      if ampMod and not isAmpMod and not isFreqMod then
        value = modulateAmplitude(channels, self, ampMod, value)
      end
      if self.adsr then
        value = value * self.adsr.sustain
      end
      return value * self.volume
    end
  }
end

local function loadOutputConfiguration(output)
  local channels = {}
  for idx, pin in pairs(output.inputs) do
    if pin.type == "chan" then
      if pin.connected[1] then
        local chanConf = loadChannelConfiguration(pin.connected[1].card)
        channels[chanConf.index] = chanConf
      end
    end
  end
  return channels
end

function cardPlot(x, y)
  local card = addCard(x, y, 33, 12, 0, 0, 33, 12, "plot", function(self)
    buf.square(self.x, self.y, 33, 12, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y + 1, 0x000000, "Plot")
    buf.text(self.x + 6, self.y + 1, 0x696969, ("x%5d"):format(self._zoom))
    buf.square(self.x + 1, self.y + 2, 31, 9, 0x1E1E1E, 0xFFFFFF, " ")
    local p = plot {background=0x1E1E1E, axisColor=0x3C3C3C, xrange={-1 / 100 * self._zoom, 1 / 100 * self._zoom}}
    local colors = {
      0x0092FF,
      0xFFB600,
      0x992480,
      0x66B600,
      0x992400,
      0xFF6DFF,
      0x33DBC0,
      0xCCFF80
    }
    local configuration = loadOutputConfiguration(self)
    for _, chan in pairs(configuration) do
      chan.plotFunction = p:fun(function()
        return chan:getValue(configuration)
      end, tostring(chan.index), colors[chan.index], 1 / sampleRate * self._zoom)
    end
    p:draw(self.x + 1, self.y + 2, 31, 9)
  end)
  card._zoom = 250
  addPin(card, 1, 0, 0xFFFFFF, 0x990000, "Ch1", "chan", side.top, true)
  addPin(card, 5, 0, 0xFFFFFF, 0x990000, "Ch2", "chan", side.top, true)
  addPin(card, 9, 0, 0xFFFFFF, 0x990000, "Ch3", "chan", side.top, true)
  addPin(card, 13, 0, 0xFFFFFF, 0x990000, "Ch4", "chan", side.top, true)
  addPin(card, 17, 0, 0xFFFFFF, 0x990000, "Ch5", "chan", side.top, true)
  addPin(card, 21, 0, 0xFFFFFF, 0x990000, "Ch6", "chan", side.top, true)
  addPin(card, 25, 0, 0xFFFFFF, 0x990000, "Ch7", "chan", side.top, true)
  addPin(card, 29, 0, 0xFFFFFF, 0x990000, "Ch8", "chan", side.top, true)
  function card:update()
    for _, pin in pairs(self.inputs) do
      if pin.connected[1] then
        pin.connected[1].card:update()
      end
    end
  end
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Zoom level (small values may cause lag)")
    local textZoom = container:addInputTextBox(1, 2, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._zoom))
    function textZoom.validator(text)
      if text:match("^%d+$") and tonumber(text) < 44100 then
        return true
      end
      return false
    end
    function textZoom.onInputFinished(text)
      self._zoom = tonumber(text) or self._zoom
    end
  end
  return card
end

function cardADSR(x, y)
  local card = addCard(x, y, 17, 10, 0, 0, 17, 9, "adsr", function(self)
    buf.square(self.x, self.y, 17, 9, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "ADSR")
    -- buf.square(self.x + 1, self.y + 1, 15, 4, 0x1E1E1E, 0xFFFFFF, " ")

    local p = plot {background=0x1E1E1E, xRange={-3000, 3000}, yRange={-1, 1}}
    p:fun(function(x)
      x = x + 3000
      if x <= self._attack and self._attack ~= 0 then
        return x / self._attack * 2 - 1
      elseif x <= self._attack + self._decay and self._decay ~= 0 then
        return ((self._decay - (x - self._attack)) / self._decay * (1 - self._sustain) + self._sustain) * 2 - 1
      elseif x <= self._attack + self._decay + 1000 then
        return self._sustain * 2 - 1
      elseif x <= self._attack + self._decay + 1000 + self._release and self._release ~= 0 then
        return ((self._release - (x - self._attack - self._decay - 1000)) / self._release * self._sustain) * 2 - 1
      else
        return -1
      end
    end, nil, 0xE1E1E1, 1)
    p:draw(self.x + 1, self.y + 1, 15, 4)

    buf.text(self.x + 1, self.y + 5, 0x696969, ("Attack  %4d ms"):format(self._attack))
    buf.text(self.x + 1, self.y + 6, 0x696969, ("Decay   %4d ms"):format(self._decay))
    local int, frac = math.modf(math.floor(self._sustain * 10000 + 0.5) / 100)
    frac = ("%02d"):format(frac * 100)
    frac = frac:gsub(".", function(c) return superNum[tonumber(c)] end)
    buf.text(self.x + 1, self.y + 7, 0x696969, ("Sustain  %3d%s%%"):format(int, frac))
    buf.text(self.x + 1, self.y + 8, 0x696969, ("Release %4d ms"):format(self._release))
  end)
  card._attack = 1000
  card._decay = 1000
  card._sustain = 0.5
  card._release = 1000
  addPin(card, 7, 9, 0xFFFFFF, 0x66DB24, " v ", "adsr", side.bottom, true, true)
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Attack (in ms)")
    local textAttack = container:addInputTextBox(1, 2, container.width, 1, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._attack))
    function textAttack.onInputFinished(text)
      self._attack = tonumber(text) and math.floor(tonumber(text)) or self._attack
    end

    container:addLabel(1, 4, container.width, 1, 0xFFFFFF, "Decay (in ms)")
    local textDecay = container:addInputTextBox(1, 5, container.width, 1, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._decay))
    function textDecay.onInputFinished(text)
      self._decay = tonumber(text) and math.floor(tonumber(text)) or self._decay
    end

    container:addLabel(1, 7, container.width, 1, 0xFFFFFF, "Sustain (in percents)")
    local textSustain = container:addInputTextBox(1, 8, container.width, 1, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._sustain * 100))
    function textSustain.onInputFinished(text)
      self._sustain = tonumber(text) and tonumber(text) / 100 or self._sustain
    end

    container:addLabel(1, 10, container.width, 1, 0xFFFFFF, "Release (in ms)")
    local textRelease = container:addInputTextBox(1, 11, container.width, 1, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, tostring(self._release))
    function textRelease.onInputFinished(text)
      self._release = tonumber(text) and math.floor(tonumber(text)) or self._release
    end

    textAttack.validator = function(text)
      if text:match("^%d+$") and tonumber(text) <= 5000 then
        return true
      end
      return false
    end
    textDecay.validator = textAttack.validator
    textRelease.validator = textAttack.validator
    function textSustain.validator(text)
      if text:match("^%d+%.?%d*$") and tonumber(text) <= 100 then
        return true
      end
      return false
    end
  end
  return card
end

function cardLFSR(x, y)
  local card = addCard(x, y, 13, 3, 0, 0, 12, 3, "lfsr", function(self)
    buf.square(self.x, self.y, 12, 3, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "LFSR noise")
    buf.text(self.x + 1, self.y + 1, 0x696969, ("v=%08X"):format(self._value))
    buf.text(self.x + 1, self.y + 2, 0x696969, ("m=%08X"):format(self._mask))
  end)
  card._value = 0
  card._mask = 0
  addPin(card, 12, 1, 0x000000, 0xFF00FF, ">", "wave", side.right, false, true)
  function card:config(container)
    container:addLabel(1, 1, container.width, 1, 0xFFFFFF, "Initial value")
    local textValue = container:addInputTextBox(1, 2, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, ("0x%X"):format(self._value))
    function textValue.validator(text)
      if tonumber(text) and tonumber(text) >= 0 and tonumber(text) <= 0xFFFFFFFF then
        return true
      end
      return false
    end
    function textValue.onInputFinished(text)
      self._value = tonumber(text) or self._value
    end

    container:addLabel(1, 6, container.width, 1, 0xFFFFFF, "Bitmask")
    local textMask = container:addInputTextBox(1, 7, container.width, 3, 0xC3C3C3, 0x3C3C3C, 0xFFFFFF, 0x000000, ("0x%X"):format(self._mask))
    function textMask.validator(text)
      if tonumber(text) and tonumber(text) >= 0 and tonumber(text) <= 0xFFFFFFFF then
        return true
      end
      return false
    end
    function textMask.onInputFinished(text)
      self._mask = tonumber(text) or self._mask
    end
  end
end

local function inBounds(x, y, bx, by, bw, bh)
  return x >= bx and y >= by and x <= bx + bw - 1 and y <= by + bh - 1
end

resetSoundCard()

local lastTouchedObject
local lastTouchX, lastTouchY
while true do
  redraw()
  local e = {event.pull(0.1)}
  if e[1] == "interrupted" then
    break
  elseif e[1] == "touch" then
    local x, y, button = table.unpack(e, 3, 5)
    local touchedPin, touchedObject
    for i = #objects, 1, -1 do
      local o = objects[i]
      if inBounds(x, y, o.x, o.y, o.w, o.h) then
        for _, pin in pairs(o.inputs) do
          if inBounds(x, y, o.x + pin.x, o.y + pin.y, unicode.len(pin.label), 1) then
            touchedPin = pin
            break
          end
        end
        if not touchedPin then
          for _, pin in pairs(o.outputs) do
            if inBounds(x, y, o.x + pin.x, o.y + pin.y, unicode.len(pin.label), 1) then
              touchedPin = pin
              break
            end
          end
        end
        local inside = inBounds(x, y, o.x + o.bx, o.y + o.by, o.x + o.bx + o.bw, o.y + o.by + o.bh)
        if inside then
          touchedObject = o
        end
        if touchedPin or inside then
          break
        end
      end
    end
    if selected then
      if touchedPin and touchedPin.isInput and touchedPin.type == selected.type and selected.card ~= touchedPin.card then
        if isin(selected, touchedPin.connected) then
          table.remove(touchedPin.connected, select(2, isin(selected, touchedPin.connected)))
          table.remove(selected.connected, select(2, isin(touchedPin, selected.connected)))
        else
          if touchedPin.single and touchedPin.connected[1] then
            local other = touchedPin.connected[1]
            table.remove(other.connected, 1)
            table.remove(touchedPin.connected, 1)
          end
          if selected.single and selected.connected[1] then
            local other = selected.connected[1]
            table.remove(other.connected, 1)
            table.remove(selected.connected, 1)
          end
          table.insert(touchedPin.connected, selected)
          table.insert(selected.connected, touchedPin)
        end
      end
      selected = false
    end
    if touchedPin and not touchedPin.isInput then
      selected = touchedPin
    end
    lastTouchedObject = touchedObject
    lastTouchX, lastTouchY = x, y
    if not selected and touchedObject then
      local _, k = isin(touchedObject, objects)
      objects[#objects], objects[k] = objects[k], objects[#objects]
      -- Right-click
      if button == 1 then
        config = lastTouchedObject
      end
    end
    if not selected and not touchedObject and button == 1 then
      -- Add a card
      cardAdd = {x, y}
    end
  elseif e[1] == "drag" then
    local x, y = table.unpack(e, 3, 5)
    if lastTouchedObject then
      local dx = x - lastTouchX
      local dy = y - lastTouchY
      lastTouchedObject.x = lastTouchedObject.x + dx
      lastTouchedObject.y = lastTouchedObject.y + dy
      lastTouchX, lastTouchY = x, y
    elseif lastTouchX and lastTouchY then
      local dx = x - lastTouchX
      local dy = y - lastTouchY
      for _, o in pairs(objects) do
        o.x, o.y = o.x + dx, o.y + dy
      end
      lastTouchX, lastTouchY = x, y
    end
  elseif e[1] == "drop" then
    lastTouchedObject, lastTouchX, lastTouchY = nil, nil, nil
  elseif e[1] == "scroll" then
    local delta = e[5]
    if not kbd.isShiftDown() then
      for _, o in pairs(objects) do
        o.y = o.y + delta
      end
    else
      for _, o in pairs(objects) do
        o.x = o.x + delta
      end
    end
  end
  local cardSound
  for _, o in pairs(objects) do
    if o.type == "sound" then
      cardSound = o
      break
    end
  end
  if not cardSound then
    resetSoundCard()
  else
    resetSoundCard()
    cardSound:update()
  end
  sound.process()
end

quit()

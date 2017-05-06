local bit32 = require("bit32")
local com = require("component")
local event = require("event")
local kbd = require("keyboard")
local unicode = require("unicode")

local buf = require("doubleBuffering")
local gui = require("GUI")

local gpu = com.gpu
local sound = com.sound

local w, h = gpu.getViewport()

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

local cardADSR, cardFM, cardPlot, cardWave, cardSoundCard, cardVolume, cardChannel, cardFrequency

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
      if pin == selected or pin.isInput and pin.type == selected.type then
        pin:draw()
      end
    end
  elseif config then
    buf.clear(0x000000, 40)
    local window = gui.fullScreenWindow()
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
      sound.setWave(self._chan, sound.modes[wave.connected[1].card._wave:lower()])
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
      if text:match("^%d+%.?%d+$") and tonumber(text) <= 100 then
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
      if text:match("^%d+%.?%d+$") and tonumber(text) < 44100 then
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
  card._intensity = 10000
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
      if text:match("^%d+%.?%d+$") and tonumber(text) <= 44100 then
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

function cardPlot(x, y)
  local card = addCard(x, y, 33, 11, 0, 0, 33, 11, "plot", function(self)
    buf.square(self.x, self.y, 33, 11, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y + 1, 0x000000, "Plot")
    buf.square(self.x + 1, self.y + 2, 31, 8, 0x1E1E1E, 0xFFFFFF, " ")
  end)
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
  return card
end

function cardADSR(x, y)
  local card = addCard(x, y, 17, 10, 0, 0, 17, 9, "adsr", function(self)
    buf.square(self.x, self.y, 17, 9, 0xFFFFFF, 0x000000, " ")
    buf.text(self.x + 1, self.y, 0x000000, "ADSR")
    buf.square(self.x + 1, self.y + 1, 15, 4, 0x1E1E1E, 0xFFFFFF, " ")
    buf.text(self.x + 1, self.y + 5, 0x696969, ("Attack  %4d"):format(self._attack))
    buf.text(self.x + 1, self.y + 6, 0x696969, ("Decay   %4d"):format(self._decay))
    local int, frac = math.modf(math.floor(self._sustain * 10000 + 0.5) / 100)
    frac = ("%02d"):format(frac * 100)
    frac = frac:gsub(".", function(c) return superNum[tonumber(c)] end)
    buf.text(self.x + 1, self.y + 7, 0x696969, ("Sustain  %3d%s%%"):format(int, frac))
    buf.text(self.x + 1, self.y + 8, 0x696969, ("Release %4d"):format(self._release))
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
      if text:match("^%d+%.?%d+$") and tonumber(text) <= 100 then
        return true
      end
      return false
    end
  end
  return card
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
        if touchedPin then
          break
        end
        if inBounds(x, y, o.x + o.bx, o.y + o.by, o.x + o.bx + o.bw, o.y + o.by + o.bh) then
          touchedObject = o
          break
        end
      end
    end
    if selected then
      if touchedPin and touchedPin.isInput then
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

resetSoundCard()

buf.clear(0x000000)
buf.draw()

gpu.setForeground(0xFFFFFF)
gpu.setBackground(0x000000)

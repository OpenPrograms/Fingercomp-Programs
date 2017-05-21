local complex = require("complex")

local function reverseBits(num, len)
  return num ~ (2^len - 1)
end

local function fftOld(x)
  local bitlen = math.ceil(math.log(#x, 2))
  local data = {}
  os.sleep()
  local lastSleep = os.clock()
  for i = 0, #x, 1 do
    data[reverseBits(i, bitlen)] = x[i]
  end

  print("GO")

  for i = 0, bitlen - 1, 1 do
    local m = 1 << i
    local n = m * 2
    local alpha = -(2 * math.pi / n)
    for k = 0, m - 1, 1 do
      local oddMp = complex.exp(complex {0, alpha * k})
      for j = k, #x - 1, n do
        local evenPart = data[j]
        local oddPart = oddMp * data[j + m]
        data[j] = evenPart + oddPart
        data[j + m] = evenPart - oddPart
        if os.clock() - lastSleep > 2.5 then
          os.sleep(0)
          lastSleep = os.clock()
        end
      end
    end
  end
  return data
end

os.sleep(0)
local lastSleep = os.clock()

local function fft(x, direct)
  if #x == 1 then return x end
  local frameHalfSize = (#x + 1) >> 1
  local frameFullSize = #x + 1
  local frameOdd = {}
  local frameEven = {}
  for i = 0, frameHalfSize - 1, 1 do
    local j = i << 1
    frameOdd[i] = x[j + 1]
    frameEven[i] = x[j]
  end
  if os.clock() - lastSleep > 2.5 then
    os.sleep(0)
    lastSleep = os.clock()
  end
  local spectrumOdd = fft(frameOdd, direct)
  local spectrumEven = fft(frameEven, direct)
  local arg = direct and (-2 * math.pi / frameFullSize) or (2 * math.pi / frameFullSize)
  local omegaPowBase = complex {math.cos(arg), math.sin(arg)}
  local omega = complex(1, 0)
  local spectrum = {}
  for j = 0, frameHalfSize - 1, 1 do
    spectrum[j] = spectrumEven[j] + omega * spectrumOdd[j]
    spectrum[j + frameHalfSize] = spectrumEven[j] - omega * spectrumOdd[j]
    omega = omega * omegaPowBase
  end
  return spectrum
end

path, depth, rate = ...
depth, rate = tonumber(depth), tonumber(rate)
print(path, depth / 8, rate)
local f = io.open(path, "r")
print("b")
local all = f:read("*a")
print("a")
f:close()
depth = math.floor(depth / 8)
local samples = {}
for i = 1, math.min(rate, #all), depth do
  local sample = all:sub(i, i + 1)
  sample = ("<i" .. depth):unpack(sample)
  samples[i] = sample / (2^(depth * 8) / 2)
end
print("s")

local requiredLen = 2^math.ceil(math.log(#samples, 2))
for i = #samples, requiredLen, 1 do
  table.insert(samples, 0)
end

for i = 1, #samples, 1 do
  samples[i - 1] = samples[i]
end

samples[#samples] = nil

print("Running FFT")

samples = fft(samples, true)
result = samples

for i = 0, #result, 1 do
  result[i] = result[i] / (#result + 1)
end

print("DECOMPOSED, GOT " .. #result .. " ENTRIES")

for i = 1, #result, 1 do
  result[i] = {i * rate / (#result + 1), result[i]:abs() / (#result + 1), select(2, result[i]:polar())}
end

for i = #result, 1, -1 do
  result[i + 1] = result[i]
end

for i = math.floor(#result / 2), #result, 1 do
  result[i] = nil
end

local component = require("component")
local unicode = require("unicode")
local event = require("event")
local term = require("term")
local gpu = component.gpu

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
    return bit32.rshift(r, 16) + bit32.rshift(g, 8) + b
  end

  local function hex2rgb(hex)
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

  function brailleMap:render(x, y)
    local sy = 0
    local fg = gpu.getForeground()
    for dy = 1, self.height, 4 do
      local sx = 0
      for dx = 1, self.width, 2 do
        local a, b, c, d, e, f, g, h =
          self:get(dx, dy), self:get(dx, dy + 1),
          self:get(dx, dy + 2), self:get(dx, dy + 3),
          self:get(dx + 1, dy), self:get(dx + 1, dy + 1),
          self:get(dx + 1, dy + 2), self:get(dx + 1, dy + 3)

        local nfg = a or b or c or d or e or f or g or h or fg

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

        if fg ~= nfg then
          gpu.setForeground(nfg)
          fg = nfg
        end
        local c = unit(a, b, c, d, e, f, g, h)
        if c ~= "⠀" then
          gpu.set(x + sx, y + sy, c)
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

  function plot:renderXAxis(vx, vy, vw, vh)
    local y = (vh * math.abs(self.ly)) / (math.abs(self.ly) + self.uy) + 1
    local x = vx
    y = vh - y + 1

    self.centerY = y

    gpu.fill(x, math.floor(y + 0.5), vw - 1, 1, "─")
    gpu.set(x + vw - 1, math.floor(y + 0.5), "→")
  end

  function plot:renderYAxis(vx, vy, vw, vh)
    local y = vy
    local x = vx + (vw * math.abs(self.lx)) / (math.abs(self.lx) + self.ux) - 1

    self.centerX = x

    gpu.fill(math.floor(x + 0.5), y + 1, 1, vh - 1, "│", true)
    gpu.set(math.floor(x + 0.5), y, "↑")
  end

  function plot:renderXYPoint(vx, vy, vw, vh)
    gpu.set(math.floor(self.centerX + 0.5), math.floor(self.centerY + 0.5), "┼")
  end

  function plot:render(vx, vy, vw, vh)
    gpu.setBackground(0x0B0C0E)
    gpu.fill(vx, vy, vw, vh, " ")

    vh = vh - self:renderLabels(vx, vy, vw, vh)
    gpu.setForeground(0x1B1C1E)
    self:renderXAxis(vx, vy, vw, vh)
    self:renderYAxis(vx, vy, vw, vh)
    self:renderXYPoint()

    self.braille = brailleMap(vw * 2, vh * 4)

    for _, fun in pairs(self.functions) do
      self:plotFunction(vx, vy, vw, vh, fun.fun, fun.color, fun.step)
    end

    self.braille:render(vx, vy)
  end

  function plot:fun(fun, color, step, label)
    table.insert(self.functions, {fun = fun, color = color, step = step, label = label})
    return self.functions[#self.functions]
  end

  function plot:renderLabels(vx, vy, vw, vh)
    local sx = 0

    for _, fun in ipairs(self.functions) do
      if fun.label then
        gpu.setForeground(fun.color)
        gpu.set(vx + sx, vy + vh - 1, fun.label)
        sx = sx + unicode.len(fun.label) + 2
      end
    end

    for _, label in ipairs(self.labels) do
      gpu.setForeground(label.color)
      gpu.set(vx + sx, vy + vh - 1, label.text)
      sx = sx + unicode.len(label.text) + 2
    end

    return 1
  end

  function plot:plotFunction(vx, vy, vw, vh, fun, color, step)
    local rw, rh = self.ux - self.lx,
      self.uy - self.ly

    for x = self.lx, self.ux, step or 0.001 do
      local y = fun(x)
      local px = self.centerX * 2 + x * vw * 2 / rw
      local py = self.centerY * 4 - y * vh * 4 / rh
      for ty = math.floor(py + 0.5), self.centerY * 4, 1 do
        self.braille:set(math.floor(px + 0.5), math.floor(ty + 0.5), color)
      end
    end
  end

  function plot:label(text, color)
    table.insert(self.labels, {text = text, color = color})
    return self.labels[#self.labels]
  end

  setmetatable(plot, {
    __call = function()
      local self = setmetatable({}, plot)

      self.functions = {}
      self.labels = {}

      self.lx = 1
      self.ux = #result

      local max = 0
      for i = 1, #result, 1 do
        max = math.max(max, result[i][2])
      end
      self.ly = 0
      self.uy = max

      return self
    end
  })
end

term.clear()

local p = plot()
p:fun(function(x)
  return result[x][2]
end, 0xFFFFFF, 1, "Spectre")

os.sleep(0)

p:render(1, 1, 80, 25)

table.sort(result, function(lhs, rhs)
  return lhs[2] > rhs[2]
end)

local s = component.sound

local i = 1
local idx = 0
while true do
  if idx == 8 or i > #result then break end
  if result[i][1] < math.huge then
    idx = idx + 1
    s.setWave(idx, s.modes.sine)
    s.setFrequency(idx, result[i][1])
    s.setVolume(idx, result[i][2] / p.uy)
    s.resetEnvelope(idx)
    s.resetFM(idx)
    s.resetAM(idx)
    s.open(idx)
    print(result[i][1], result[i][2], result[i][3])
  end
  i = i + 1
end

while not event.pull(1, "interrupted") do
  s.delay(1000)
  s.process()
end

term.clear()

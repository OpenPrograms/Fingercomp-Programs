local component = require("component")
local fs = require("filesystem")
local shell = require("shell")
local term = require("term")
local unicode = require("unicode")

local complex = require("complex")

local gpu = component.gpu

local function reverseBits(num, len)
  local result = 0
  local n = 1 << len
  local nrev = num
  for i = 1, len - 1, 1 do
    num = num >> 1
    nrev = nrev << 1
    nrev = nrev | (num & 1)
  end
  nrev = nrev & (n - 1)
  return nrev
end

local function fft(x)
  local bitlen = math.ceil(math.log(#x, 2))
  local data = {}
  for i = 0, #x, 1 do
    data[reverseBits(i, bitlen)] = complex(x[i])
  end

  for s = 1, bitlen, 1 do
    local m = 2^s
    local hm = m * 0.5
    local omegaM = (complex{0, -2 * math.pi / m}):exp()
    for k = 0, #x, m do
      local omega = complex(1)
      for j = 0, hm - 1 do
        local t = omega * data[k + j + hm]
        local u = data[k + j]
        data[k + j] = u + t
        data[k + j + hm] = u - t
        omega = omega * omegaM
      end
    end
  end
  return data
end

path, depth, rate, sampleSize, step, len = ...
depth, rate = tonumber(depth), tonumber(rate)
sampleSize = tonumber(sampleSize) or 1024
step = tonumber(step)

local f = io.open(path, "rb")
local total = fs.size(shell.resolve(path))

depth = math.floor(depth / 8)
len = tonumber(len) or total / rate / depth

total = len * rate * depth

local chans = {}

sampleSize = 2^math.ceil(math.log(sampleSize, 2)) - 1
step = math.floor((sampleSize + 1) / step + .5)
local sleep = step / rate

print("Loading " .. ("%.2f"):format(len) .. "s of " .. path .. ": pcm_s" .. (depth * 8) .. (depth > 1 and "le" or "") .. " @ " .. rate .. " Hz [" .. math.floor(sampleSize + 1) .. " samples -> " .. math.floor(step) .. "]")

local iTime = os.clock()
local startTime = iTime

os.sleep(0)
local lastSleep = os.clock()

local shift = 0

while shift < total do
  local samples = {}
  for i = 1, math.min(sampleSize, total - shift) * depth, depth do
    local sample = f:read(depth)
    sample = ("<i" .. depth):unpack(sample)
    samples[i] = sample / (2^(depth * 8) / 2)
  end

  local requiredLen = 2^math.ceil(math.log(#samples, 2))
  for i = #samples, requiredLen - 1, 1 do
    table.insert(samples, 0)
  end

  for i = 1, #samples, 1 do
    samples[i - 1] = samples[i]
  end

  samples[#samples] = nil

  samples = fft(samples, true)
  result = samples

  for i = 1, #result, 1 do
    result[i] = {i * rate / (#result + 1), result[i]:abs() / (#result + 1), select(2, result[i]:polar())}
  end

  for i = #result, 1, -1 do
    result[i + 1] = result[i]
  end

  for i = math.floor(#result / 2), #result, 1 do
    result[i] = nil
  end

  table.sort(result, function(lhs, rhs)
    return lhs[2] > rhs[2]
  end)

  for i = 1, 8, 1 do
    table.insert(chans, result[i][1])
    table.insert(chans, result[i][2])
  end

  if total - shift < sampleSize then
    break
  end
  shift = shift + step
  term.clearLine()
  local dig = math.ceil(math.log(total, 10))
  io.write(("%" .. dig .. ".0f B processed out of %" .. dig .. ".0f B (took %.3fs)"):format(shift, total, os.clock() - iTime))
  iTime = os.clock()
  if os.clock() - lastSleep > 2.5 then
    os.sleep(0)
    lastSleep = os.clock()
  end
end

f:close()

term.clearLine()
print(("%.0f B processed for %.3fs (%.2f B/s)"):format(total, os.clock() - startTime, total / (os.clock() - startTime)))

os.sleep(0)

local s = component.sound

local maxAmplitude = 0
for i = 2, #chans, 2 do
  maxAmplitude = math.max(maxAmplitude, chans[i])
end

local iteration = 1

for sample = 1, #chans, 8 * 2 do
  term.clearLine()
  io.write(("Playing: %.2fs (%3.0f%%)"):format(iteration * sleep, iteration * sleep / len * 100))
  local i = 1
  for chan = sample, sample + 8 * 2 - 1, 2 do
    s.setWave(i, s.modes.sine)
    s.setFrequency(i, chans[chan])
    s.setVolume(i, chans[chan + 1] / maxAmplitude)
    s.resetEnvelope(i)
    s.resetFM(i)
    s.resetAM(i)
    s.open(i)
    i = i + 1
  end
  s.delay(sleep * 1000)
  while not s.process() do
    os.sleep(0.05)
  end
  os.sleep(sleep)
  iteration = iteration + 1
end

s.process()

print("\n\nExiting")

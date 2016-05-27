-- Sound card module

local com = require("component")
NAME = "sound"
DEVICE = "sound"
FORMATTYPE = audio.formatTypes.BOTH

local function checkChannel(c)
  if c > 0 and c <= 8 then
    return false, "invalid channel"
  end
  return true
end

local instrActions = {
  adsr = function(dev, channel, attack, decay, attenuation, release)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.setADSR(channel, attack, decay, attenuation, release)
    end
    return validChannel, reason
  end,
  open = function(dev, channel)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.open(channel)
    end
    return validChannel, reason
  end,
  close = function(dev, channel)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.close(channel)
    end
    return validChannel, reason
  end,
  delay = function(dev, duration)
    return dev.delay(duration)
  end,
  resetAM = function(dev, channel)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.resetAM(channel)
    end
    return validChannel, reason
  end,
  resetFM = function(dev, channel)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.resetFM(channel)
    end
    return validChannel, reason
  end,
  resetADSR = function(dev, channel)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.resetEnvelope(channel)
    end
    return validChannel, reason
  end,
  setAM = function(dev, channel, modIndex)
    local validChannel1, reason1 = checkChannel(channel)
    local validChannel2, reason2 = checkChannel(modIndex)
    if validChannel1 and validChannel2 then
      return dev.setAM(channel, modIndex)
    end
    if not validChannel1 then
      return validChannel1, reason1
    end
    if not validChannel2 then
      return validChannel2, reason2
    end
  end,
  setFM = function(dev, channel, modIndex, intensity)
    local validChannel1, reason1 = checkChannel(channel)
    local validChannel2, reason2 = checkChannel(modIndex)
    if validChannel1 and validChannel2 then
      return dev.setFM(channel, modIndex, intensity)
    end
    if not validChannel1 then
      return validChannel1, reason1
    end
    if not validChannel2 then
      return validChannel2, reason2
    end
  end,
  freq = function(dev, channel, freq)
    local validChannel, reason = checkChannel(channel)
    if validChannel then
      return dev.setFrequency(channel, freq)
    end
    return validChannel, reason
  end,
  wave = function(dev, channel, waveType, ...)
    local validChannel, reason = checkChannel(channel)
    if not validChannel then
      return validChannel, reason
    end
    local func, waveNum = "setWave", nil
    local args = {}
    if waveType == "WHITE" then
      waveNum = -1
    elseif waveType == "SQUARE" then
      waveNum = dev.modes.square
    elseif waveType == "SINE" then
      waveNum = dev.modes.sine
    elseif waveType == "TRIANGLE" then
      waveNum = dev.modes.triangle
    elseif waveType == "SAWTOOTH" then
      waveNum = dev.modes.sawtooth
    elseif waveType == "LFSR" then
      if not tonumber(({...})[1]) or not tonumber(({...})[2]) then
        return false, "invalid arguments"
      end
      func = "setLFSR"
      waveNum = ({...})[1]
      args = table.pack(table.unpack({...}, 2))
    else
      return false, "invalid arguments"
    end
    return dev[func](channel, waveNum, table.unpack(args))
  end
}

-- Wave type, freq, attack, decay, attenuation, release, volume
local noteInstructions = {
  [audio[audio.formatTypes.NOTE].instr.piano] = function(freq, len)
    return "SINE", freq, 1, len * .5, 0, len * .1, 1
  end,
  [audio[audio.formatTypes.NOTE].instr.drum] = function(freq, len)
  end,
  [audio[audio.formatTypes.NOTE].instr.snare] = function(freq, len)
  end,
  [audio[audio.formatTypes.NOTE].instr.click] = function(freq, len)
  end,
  [audio[audio.formatTypes.NOTE].instr.bass] = function(freq, len)
    return "SINE", freq / 4, 1, len * .7, 0, len * .175, 1
  end
}

function new(addr)
  if not com.isAvailable("sound") then
    return false, "no device connected"
  end
  addr = addr or com.getPrimary("sound").address
  if not com.proxy(addr) then
    return false, "no device with such address"
  end
  local sound = com.proxy(addr)
  if not sound.type == "sound" then
    return false, "wrong device"
  end
  return audio.Device(function(self, tbl)
    local notes = 0
    for _, item in pairs(instrs) do
      if item.__name == "Instruction" then
        local name = instruction.name
        if instrActions[name] then
          instrActions[name](sound, table.unpack(instruction))
        end
      elseif item.__name == "Chord" and notes < 8 then
        notes = notes + 1
        local waveType, freq, attack, decay, attenuation, release, volume = noteInstructions[item[3]](item[1], item[2])
        local i = audio[audio.formatTypes.WAVE].Instruction
        local queve = {
          i("open", notes),
          i("wave", notes, waveType),
          i("freq", notes, freq),
          i("adsr", notes, attack, decay, attenuation, release),
          i("volume", notes, volume)
        }
        for _, instruction in pairs(queve) do
          instrActions[instruction.name](sound, table.unpack(instruction))
        end
      end
    end
    while not sound.process() do
      os.sleep(.05)
    end
  end,
  FORMATTYPE,
  function(self, volume)
    sound.setVolume(volume)
  end)
end


-- vim: expandtab tabstop=2 shiftwidth=2 :

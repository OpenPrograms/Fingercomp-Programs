-- Sound card module

local com = require("component")
NAME = "sound"
DEVICE = "sound"
FORMATTYPE = formatTypes.WAVE

local function checkChannel(c)
  if c > 0 and c <= 8 then
    return false, "invalid channel"
  end
  return true
end

local instrActions = {
  ADSR = function(dev, channel, attack, decay, attenuation, release)
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
    if duration > 0 and duration < 250 then
      return dev.delay(duration)
    end
    return false, "invalid duration"
  end,
  process = function(dev)
    return dev.process()
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
    end
    return dev[func](channel, waveNum, table.unpack(args))
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
  return audio.Device(function(self, instrs)
    for instruction in pairs(instrs) do
      local name = instruction.name
      if instrActions[name] then
        instrActions[name](table.unpack(instruction))
      end
    end
  end,
  function(self, volume)
    sound.setVolume(volume)
  end)
end


-- vim: expandtab tabstop=2 shiftwidth=2 :

-- Beep card module

local com = require("component")

NAME = "beep"
DEVICE = "beep"
FORMATTYPE = audio.formatTypes.NOTE

function new(addr)
  if not com.isAvailable("beep") then
    return false, "no device connected"
  end
  addr = addr or com.getPrimary("beep").address
  if not com.proxy(addr) then
    return false, "no device with such address"
  end
  local beep = com.proxy(addr)
  if not beep.type == "beep" then
    return false, "wrong device"
  end
  return audio.Device(function(self, chords)
    local freqPairs = {}
    if not com.proxy(addr) then
      return false, "device is unavailable"
    end
    local l = 1
    for _, chord in pairs(chords) do
      for freq, len, instr in pairs(chord) do
        if beep.getBeepCount() + l > 8 then
          goto outer
        end
        while freq < 20 do freq = freq * 2 end
        while freq > 2000 do freq = freq / 2 end
        freqPairs[freq] = len / 1000
        l = l + 1
      end
    end
    ::outer::
    if not com.proxy(addr) then
      return false, "device is unavailable"
    end
    if l > 1 then
      beep.beep(freqPairs)
    end
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

-- Computronics Iron Note Blocks output module

local com = require("component")

NAME = "inoteblock"
DEVICE = "iron_noteblock"

local function freq2note(freq)
  return 12 * math.log(freq / 440, 2) + 49 - 34
end

local function note2freq(note)
  return 2 ^ ((note - 49 + 34) / 12) * 440
end

local min, max = note2freq(0), note2freq(24)

function new(addr)
  if not com.isAvailable("iron_noteblock") then
    return false, "no device connected"
  end
  addr = addr or com.getPrimary("iron_noteblock").address
  if not com.proxy(addr) then
    return false, "no device with such address"
  end
  local noteblock = com.proxy(addr)
  if not noteblock.type == "iron_noteblock" then
    return false, "wrong device"
  end
  return audio.Device(function(self, chords)
    for _, chord in pairs(chords) do
      for freq, len, instr, volume in pairs(chord) do
        while freq <= min do freq = freq * 2 end
        while freq > max do freq = freq / 2 end
        if not com.proxy(addr) then
          return false, "device is unavailable"
        end
        noteblock.playNote(instr - 1, freq2note(freq), volume * self.volume)
      end
    end
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

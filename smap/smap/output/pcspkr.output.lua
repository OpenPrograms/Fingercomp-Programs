--  computer.beep()

NAME = "pcspkr"
DEVICE = "computer"
FORMATTYPE = audio.formatTypes.NOTE

local comp = require("computer")

function new()
  return audio.Device(function(self, chords)
    for _, chord in pairs(chords) do
      for freq, len, instr in pairs(chord) do
        while freq < 20 do freq = freq * 2 end
        while freq > 2000 do freq = freq / 2 end
        comp.beep(freq, len / 1000)
      end
    end
  end, FORMATTYPE)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

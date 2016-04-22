--  computer.beep()

NAME = "pcspkr"

local comp = require("computer")

function new()
  return audio.Device(function(dev, chords)
    for _, chord in pairs(chords) do
      for freq, len, instr in pairs(chord) do
        comp.beep(freq, len)
      end
    end
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

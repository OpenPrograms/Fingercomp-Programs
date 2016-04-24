-- Beep card module

NAME = "beep"

function new()
  local beep = require("component").beep
  return audio.Device(function(dev, chords)
    local freqPairs = {}
    local l = 1
    for _, chord in pairs(chords) do
      for freq, len, instr in pairs(chord) do
        if l > 8 then
          goto outer
        end
        while freq < 20 do freq = freq * 2 end
        while freq > 2000 do freq = freq / 2 end
        freqPairs[freq] = len
      end
    end
    ::outer::
    beep.beep(freqPairs)
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

-- Computronics Iron Note Blocks output module

NAME = "inoteblock"

local function freq2note(freq)
  return 12 * math.log(freq / 440, 2) + 49 - 34
end

function new()
  local noteblock = require("component").iron_noteblock
  return audio.Device(function(buf, chords)
    for _, chord in pairs(chords) do
      for freq, len, instr in pairs(chord) do
        noteblock.playNote(instr - 1, freq2note(freq), 1)
      end
    end
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

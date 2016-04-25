-- Computronics Iron Note Blocks output module

NAME = "inoteblock"

local function freq2note(freq)
  return 12 * math.log(freq / 440, 2) + 49 - 34
end

local function note2freq(note)
  return 2 ^ ((note - 49 + 34) / 12) * 440
end

local min, max = note2freq(0), note2freq(24)

function new()
  local noteblock = require("component").iron_noteblock
  return audio.Device(function(dev, chords)
    for _, chord in pairs(chords) do
      for freq, len, instr, volume in pairs(chord) do
        while freq <= min do freq = freq * 2 end
        while freq > max do freq = freq / 2 end
        noteblock.playNote(instr - 1, freq2note(freq), volume)
      end
    end
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

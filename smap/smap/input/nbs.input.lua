-- Note Block Studio files reader
-- Used: http://pastebin.com/yrtLYBhz

local fs = require("filesystem")

NAME = "nbs"
FORMATTYPE = audio.formatTypes.NOTE

local noteAudio = audio[FORMATTYPE]

local function note2freq(note)
  return 2 ^ ((note - 49) / 12) * 440
end

local function byte(file)
  return string.byte(file:read(1))
end

local function nbsInt16(b1, b2)
  local n = b1 + 0x100 * b2
  n = (n > 0x8000) and (n - 0x7fff) or n
  return n
end

local function nbsInt32(b1, b2, b3, b4)
  local n = b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
  n = (n > 0x7fffffff) and (n - 0x100000000) or n
  return n
end

local function nbsStr(file)
  local strlen = nbsInt32(byte(file), byte(file), byte(file), byte(file))
  return file:read(strlen)
end

local instr = {
  [0] = noteAudio.instr.piano,
  [1] = noteAudio.instr.bass,
  [2] = noteAudio.instr.drum,
  [3] = noteAudio.instr.snare,
  [4] = noteAudio.instr.click
}

function guess(path)
  local file, rsn = io.open(path, "rb")
  if not file then
    return false, rsn
  end
  local result, rsn = pcall(function()
    local length = nbsInt16(byte(file), byte(file))

    local height = nbsInt16(byte(file), byte(file))
    local name = nbsStr(file)
    local author = nbsStr(file)
    local originAuthor = nbsStr(file)
    local desc = nbsStr(file)

    local tempo = nbsInt16(byte(file), byte(file)) / 100
  end)
  if result then
    return true
  end
end

function loadpath(path)
  if fs.isDirectory(path) then
    return false, "directories are not supported"
  end

  local track

  local function loadBuffer(file, tempo, size)
    local buf = noteAudio.Buffer{to=-1, func=function(b)
      local newBuf = loadBuffer(file, track.tempo, size)
      if newBuf then
        track:add(newBuf)
      end
    end}

    local tick = 0

    while true do
      if #buf.data >= size then
        break
      end

      local jumps = 0

      if pcall(function()
        jumps = nbsInt16(byte(file), byte(file))
      end) ~= true then
        file:close()
        return false, "not a NBS file"
      end

      if jumps == 0 then
        break
      end

      tick = tick + jumps

      local chord = noteAudio.Chord()
      if pcall(function()
        while true do
          local curLayer = nbsInt16(byte(file), byte(file))
          if curLayer == 0 then
            break
          end
          local instrument = byte(file)
          local note = byte(file)
          local freq = note2freq(note)
          chord:add(freq, 1000 / tempo, instr[instrument], 1)
        end
      end) ~= true then
        file:close()
        return false, "corrupted file"
      end

      buf:add({tick, chord})
    end

    if #buf.data > 0 then
      return buf
    end

    file:close()

    return nil
  end

  local file = io.open(path, "rb")
  local length, height, name, author, originAuthor, desc, tempo
  if pcall(function()
    length = nbsInt16(byte(file), byte(file))

    height = nbsInt16(byte(file), byte(file))
    name = nbsStr(file)
    author = nbsStr(file)
    originAuthor = nbsStr(file)
    desc = nbsStr(file)

    tempo = nbsInt16(byte(file), byte(file)) / 100
  end) ~= true then
    file:close()
    return false, "not a NBS file"
  end

  local trash = file:read(23)
  trash = nbsStr(file)

  track = noteAudio.Track{tempo = tempo}
  track:setInfo({
    name = name,
    author = author,
    comment = (originAuthor and originAuthor ~= "" and "Originally created by: " .. originAuthor .. ".\n" or "") .. (desc or "")
  })
  local firstBuffer = loadBuffer(file, tempo, math.huge)

  if firstBuffer then
    track:add(firstBuffer)
  end

  return audio.Music(track, function()
    file:close()
  end)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

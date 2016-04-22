-- Note Block Studio files reader
-- Used: http://pastebin.com/yrtLYBhz

local function note2freq(note)
  return freq = 2 ^ ((note - 49) / 12) * 440
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

function loadpath(path)
  if fs.isDirectory(path) then
    return false, "directories are not supported"
  end

  local track

  local function loadBuffer(file, curTick, tempo, size)
    local buf = audio.Buffer{to=10, function(b)
      local newBuf = loadBuffer(file, b.pos, track.tempo, size)
      if newBuf then
        track:add(newBuf)
      end
    end}

    while true do
      local jumps = nbsInt16(byte(file), byte(file))

      if jumps == 0 then
        break
      end

      local tick = curTick + jumps
      if #buf.data > size then
        break
      end
      
      local chord = audio.Chord()
      while true do 
        local curLayer = nbsInt16(byte(file), byte(file))
        if curLayer == 0 then
          break
        end
        local instr = byte(file)
        local note = byte(file)
        local freq = note2freq(note)
        chord:add{freq=freq, length=(1 / tempo), instr}
      end

      buf:add({tick, chord})
    end

    if #buf.data > 0 then
      return buf
    end

    return nil
  end

  local file = io.open(path, "rb")
  local length = nbsInt16(byte(file), byte(file))

  local height = nbsInt16(byte(file), byte(file))
  local name = nbsStr(file)
  local author = nbsStr(file)
  local originAuthor = nbsStr(file)
  local desc = nbsStr(file)

  local tempo = nbsInt16(byte(file), byte(file))

  local trash = file:read(23)
  trash = nbsStr(file)

  track = audio.Track{tempo = tempo}
  local firstBuffer = loadBuffer(file, 0, tempo, 60)

  if firstBuffer then
    track:add(firstBuffer)
  end

  return audio.Music(track)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

-- MIDI input module.

local DEBUG = false
NAME = "midi"

local fs = require("filesystem")
local bit32 = bit32 or require("bit32")

local function instr(i, ch)
  if ch ~= 10 then
    if i >= 1 and i <= 32 or i >= 41 and i <= 112 then
      return audio.instr.piano
    elseif i >= 33 and i <= 40 or i >= 113 and i <= 120 then
      return audio.instr.bass
    end
  else
    return audio.instr.bass
  end
end

local function freq(n)
  if type(n) == "string" then
    n = string.lower(n)
    if tonumber(notes[n])~=nil then
      return 2 ^ ((tonumber(notes[n])-69)/12*440)
    else
      error("Wrong input "..tostring(n).." given to note.freq, needs to be <note>[semitone sign]<octave>, e.g. A#0 or Gb4",2)
    end
  elseif type(n) == "number" then
    return 2 ^ ((n-69)/12)*440
  else
    error("Wrong input "..tostring(n).." given to note.freq, needs to be a number or a string",2)
  end
end

local function parseVarInt(s, bits) -- parses multiple bytes as an integer
  if not s then
    f:close()
    error("error parsing file")
  end
  bits = bits or 8
  local mask = bit32.rshift(0xFF, 8 - bits)
  local num = 0
  for i = 1, s:len() do
    num = num + bit32.lshift(bit32.band(s:byte(i), mask), (s:len() - i) * bits)
  end
  return num
end

function guess(path)
  local f, rsn = io.open(path, "rb")
  if not f then
    return false, rsn
  end
  local id = f:read(4)
  local len = parseVarInt(f:read(4))
  f:close()
  if id == "MThd" and len == 6 then
    return true
  end
end

function loadpath(path)
  if fs.isDirectory(path) then
    return false, "directories are not supported"
  end

  local f, rsn = io.open(path, "rb")
  if not f then
    return false, rsn
  end

  -- This code is borrowed from Sangar's awesome program, midi.lua
  -- Check it out here: https://github.com/OpenPrograms/Sangar-Programs/blob/master/midi.lua

  local function readChunkInfo() -- reads chunk header info
    local id = f:read(4)
    if not id then
      return
    end
    return id, parseVarInt(f:read(4))
  end

  
  -- Read the file header and with if file information.
  local id, size = readChunkInfo()
  if id ~= "MThd" or size ~= 6 then
    f:close()
    return false, "error parsing header (" .. id .. "/" .. size .. ")"
  end

  local format = parseVarInt(f:read(2))
  local tracks = parseVarInt(f:read(2))
  local delta = parseVarInt(f:read(2))

  if DEBUG then
    print(format, tracks, delta)
  end

  if format < 0 or format > 2 then
    f:close()
    return false, "unknown format"
  end

  local formatName = ({"single", "synchronous", "asynchronous"})[format + 1]
  if DEBUG then
    print(string.format("Found %d %s tracks.", tracks, formatName))
  end

  if format == 2 then
    f:close()
    return false, "asynchronous tracks are not supported"
  end

  -- Figure out our time system and prepare accordingly.
  local time = {division = bit32.band(0x8000, delta) == 0 and "tpb" or "fps"}
  if time.division == "tpb" then
    time.tpb = bit32.band(0x7FFF, delta)
    time.mspb = 500000
    function time.tick()
      return time.mspb / time.tpb
    end
    if DEBUG then
      print(string.format("Time division is in %d ticks per beat.", time.tpb))
    end
  else
    time.fps = bit32.band(0x7F00, delta)
    time.tpf = bit32.band(0x00FF, delta)
    function time.tick()
      return 1000000 / (time.fps * time.tpf)
    end
    if DEBUG then
      print(string.format("Time division is in %d frames per second with %d ticks per frame.", time.fps, time.tpf))
    end
  end
  function time.calcDelay(later, earlier)
    return (later - earlier) * time.tick() / 1000000
  end

  local totalOffset = 0
  local totalLength = 0
  local tracks = {}
  while true do
    local id, size = readChunkInfo()
    if not id then
      break
    end
    if id == "MTrk" then
      local track = {}
      local cursor = 0
      local start, offset = f:seek(), 0
      local inSysEx = false
      local running = 0

      local function read(n)
        n = n or 1
        if n > 0 then
          offset = offset + n
          return f:read(n)
        end
      end
      local function readVariableLength()
        local total = ""
        for i = 1, math.huge do
          local part = read()
          total = total .. part
          if bit32.band(0x80, part:byte(1)) == 0 then
            return parseVarInt(total, 7)
          end
        end
      end
      local function parseVoiceMessage(event)
        local channel = bit32.band(0xF, event)
        local note = parseVarInt(read())
        local velocity = parseVarInt(read())
        return channel, note, velocity
      end
      local currentNoteEvents = {}
      local function noteOn(cursor, channel, note, velocity)
        track[cursor] = {channel, note, velocity}
        if not currentNoteEvents[channel] then
          currentNoteEvents[channel] = {}
        end
        currentNoteEvents[channel][note] = {event=track[cursor], tick=cursor}
      end
      local function noteOff(cursor, channel, note, velocity)
        if not (currentNoteEvents[channel] and currentNoteEvents[channel][note] and currentNoteEvents[channel][note].event) then return end
        table.insert(currentNoteEvents[channel][note].event
            , time.calcDelay(cursor, currentNoteEvents[channel][note].tick))
        currentNoteEvents[channel][note] = nil
      end

      while offset < size do
        cursor = cursor + readVariableLength()
        totalLength = math.max(totalLength, cursor)
        local test = parseVarInt(read())
        if inSysEx and test ~= 0xF7 then
          f:close()
          return false, "corrupt file: could not find continuation of divided sysex event"
        end
        local event
        if bit32.band(test, 0x80) == 0 then
          if running == 0 then
            f:close()
            return false, "corrupt file: invalid running status"
          end
          f.bufferRead = string.char(test) .. f.bufferRead
          offset = offset - 1
          event = running
        else
          event = test
          if test < 0xF0 then
            running = test
          end
        end
        local status = bit32.band(0xF0, event)
        if status == 0x80 then -- Note off.
          local channel, note, velocity = parseVoiceMessage(event)
          noteOff(cursor, channel, note, velocity)
        elseif status == 0x90 then -- Note on.
          local channel, note, velocity = parseVoiceMessage(event)
          if velocity == 0 then
            noteOff(cursor, channel, note, velocity)
          else
            noteOn(cursor, channel, note, velocity)
          end
        elseif status == 0xA0 then -- Aftertouch / key pressure
          parseVoiceMessage(event) -- not handled
        elseif status == 0xB0 then -- Controller
          parseVoiceMessage(event) -- not handled
        elseif status == 0xC0 then -- Program change
          parseVarInt(read()) -- not handled
        elseif status == 0xD0 then -- Channel pressure
          parseVarInt(read()) -- not handled
        elseif status == 0xE0 then -- Pitch / modulation wheel
          parseVarInt(read(2), 7) -- not handled
        elseif event == 0xF0 then -- System exclusive event
          local length = readVariableLength()
          if length > 0 then
            read(length - 1)
            inSysEx = read(1):byte(1) ~= 0xF7
          end
        elseif event == 0xF1 then -- MIDI time code quarter frame
          parseVarInt(read()) -- not handled
        elseif event == 0xF2 then -- Song position pointer 
          parseVarInt(read(2), 7) -- not handled
        elseif event == 0xF3 then -- Song select
          parseVarInt(read(2), 7) -- not handled
        elseif event == 0xF7 then -- Divided system exclusive event
          local length = readVariableLength()
          if length > 0 then
            read(length - 1)
            inSysEx = read(1):byte(1) ~= 0xF7
          else
            inSysEx = false
          end
        elseif event >= 0xF8 and event <= 0xFE then -- System real-time event
          -- not handled
        elseif event == 0xFF then
          -- Meta message.
          local metaType = parseVarInt(read())
          local length = parseVarInt(read())
          local data = read(length)

          if metaType == 0x00 then -- Sequence number
            track.sequence = parseVarInt(data)
          elseif metaType == 0x01 then -- Text event
          elseif metaType == 0x02 then -- Copyright notice
          elseif metaType == 0x03 then -- Sequence / track name
            track.name = data
          elseif metaType == 0x04 then -- Instrument name
            track.instrument = data
          elseif metaType == 0x05 then -- Lyric text
          elseif metaType == 0x06 then -- Marker text
          elseif metaType == 0x07 then -- Cue point
          elseif metaType == 0x20 then -- Channel prefix assignment
          elseif metaType == 0x2F then -- End of track
            track.eot = cursor
          elseif metaType == 0x51 then -- Tempo setting
            track[cursor] = parseVarInt(data)
          elseif metaType == 0x54 then -- SMPTE offset
          elseif metaType == 0x58 then -- Time signature
          elseif metaType == 0x59 then -- Key signature
          elseif metaType == 0x7F then -- Sequencer specific event
          end
        else
          f:seek("cur", -9)
          local area = f:read(16)
          local dump = ""
          for i = 1, area:len() do
            dump = dump .. string.format(" %02X", area:byte(i))
            if i % 4 == 0 then
              dump = dump .. "\n"
            end
          end
          f:close()
          return false, string.format("midi file contains unhandled event types:\n0x%X at offset %d/%d\ndump of the surrounding area:\n%s", event, offset, size, dump)
        end
      end
      -- turn off any remaining notes
      for iChannel, iNotes in pairs(currentNoteEvents) do
        for iNote, iEntry in pairs(currentNoteEvents[iChannel]) do
          noteOff(cursor, iChannel, iNote)
        end
      end
      local delta = size - offset
      if delta ~= 0 then
        f:seek("cur", delta)
      end
      totalOffset = totalOffset + size
      table.insert(tracks, track)
    else
      if DEBUG then
        print(string.format("Encountered unknown chunk type %s, skipping.", id))
      end
      f:seek("cur", size)
    end
  end

  f:close()

  local t = audio.Track{tempo = 1 / time.calcDelay(1, 0)}
  local buf = audio.Buffer{func=function() end, to=0} -- All tracks are already loaded

  local trs = #tracks
  for tick = 1, totalLength do
    local chord
    for trnum = 1, trs, 1 do
      if tracks[trnum][tick] then
        if type(tracks[trnum][tick]) == "number" then
          time.mspb = tracks[trnum][tick]
        elseif type(tracks[trnum][tick]) == "table" then
          chord = chord or audio.Chord()
          local channel, noteNum, velocity, duration = table.unpack(tracks[trnum][tick])
          if duration then -- Semi-broken MIDI files fix
            chord:add(freq(noteNum), duration * 1000, instr(tracks[trnum].instrument or 1, channel) or 1, velocity / 0x80)
          end
        end
      end
      event = nil
      tracks[trnum][tick] = nil
    end
    if chord then
      buf:add({tick, chord})
    end
  end
  tracks = nil
  t:add(buf)

  return audio.Music(t)
end

-- vim: expandtab tabstop=2 shiftwidth=2 :

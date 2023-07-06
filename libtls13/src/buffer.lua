-- A buffer for parsing things, backed by a string.

local bitstring = require("tls13.asn.bitstring")
local errors = require("tls13.error")
local util = require("tls13.util")

local lib = {}

local rewindingMeta = {
  __index = function(self, method)
    local f = function(self, ...)
      local buf = assert(self[1])
      local result, err = buf[method](buf, ...)

      if not result then
        buf:restoreState(self)
      end

      return result, err
    end

    self[method] = f

    return f
  end,

  __call = function(self, f)
    local buf = self[1]
    local result, err = f()

    if not result then
      buf:restoreState(self)
    end

    return result, err
  end,
}

local meta = {
  __index = {
    pushLimit = function(self, n, pos)
      pos = pos or self.__pos
      local currentLimit = self:getLimit()
      local to = self.__pos + n

      if math.ult(currentLimit.to, to) then
        -- enforce limits set previously
        self.__limit = {
          to = currentLimit.to,
          pos = currentLimit.pos,
          parent = self.__limit,
        }
      else
        self.__limit = {
          to = to,
          pos = pos,
          parent = self.__limit,
        }
      end
    end,

    popLimit = function(self)
      assert(self.__limit.parent, "unbalanced pop")
      self.__limit = self.__limit.parent
    end,

    getLimit = function(self)
      return self.__limit
    end,

    withLimit = function(self, n, f, pos)
      self:pushLimit(n, pos)
      local result, err = f(self)
      self:popLimit()

      return result, err
    end,

    pushContext = function(self, tag, pos)
      pos = pos or self.__pos
      self.__context = {
        tag = tag,
        pos = pos,
        parent = self.__context,
      }
    end,

    popContext = function(self)
      assert(self.__context, "unbalanced pop")
      self.__context = self.__context.parent
    end,

    withContext = function(self, tag, f, pos)
      self:pushContext(tag, pos)
      local result, err = f(self)
      self:popContext()

      return result, err
    end,

    makeParserErrorWithState = function(self, state, err, ...)
      local context

      if not state.context then
        context = ("at byte 0x%x"):format(state.pos)
      else
        context = {}
        local component = state.context

        while component ~= nil do
          table.insert(context, ("%s at 0x%x"):format(
            component.tag,
            component.pos
          ))
          component = component.parent
        end

        util.reverse(context)

        context = table.concat(context, " -> ")
          .. (" (byte 0x%x)"):format(state.pos)
      end

      return err(context, ...)
    end,

    makeParserError = function(self, err, ...)
      return self:makeParserErrorWithState(self:saveState(), err, ...)
    end,

    saveState = function(self)
      return {
        pos = self.__pos,
        limit = self.__limit,
        context = self.__context,
      }
    end,

    restoreState = function(self, state)
      self.__pos = state.pos
      self.__limit = state.limit
      self.__context = state.context
    end,

    rewinding = function(self)
      local state = self:saveState()
      state[1] = self

      return setmetatable(state, rewindingMeta)
    end,

    read = function(self, n)
      n = n or 1

      if n <= 0 then
        return ""
      end

      local pos = self.__pos
      local result = self.__s:sub(pos, pos + n - 1)
      local limit = self:getLimit()
      pos = pos + #result
      self.__pos = math.min(pos, limit.to)

      if pos > limit.to then
        return nil, self:makeParserError(
          errors.parser.lengthLimitExceeded,
          limit.pos, pos - limit.to
        )
      end

      if #result < n then
        return nil, self:makeParserError(
          errors.parser.eof.knownSize, n - #result
        )
      end

      return result
    end,

    remaining = function(self)
      return #self.__s - self.__pos + 1
    end,

    startsWith = function(self, bytes)
      return self.__s:sub(self.__pos, self.__pos + #bytes) == bytes
    end,

    getLimitRemaining = function(self)
      return self:getLimit().to - self.__pos
    end,

    peek = function(self, n, count)
      n = n or 1
      count = count or 1

      return self.__s:sub(self.__pos + n - 1, self.__pos + n + count - 2)
    end,

    expectEof = function(self)
      if self:remaining() > 0 then
        return nil, self:makeParserError(
          errors.parser.unexpected.trailingByte,
          self:remaining()
        )
      end

      return true
    end,

    pos = function(self)
      return self.__pos
    end,

    expect = function(self, bytes, expectedMessage)
      local actual, err = self:rewinding():read(#bytes)

      if not actual and err ~= errors.parser.eof then
        return nil, err
      end

      if #actual < bytes then
        return nil, self:makeParserError(
          errors.parser.eof.knownData,
          expectedMessage or util.toHex(bytes), util.toHex(actual)
        )
      end

      if actual ~= bytes then
        return nil, self:makeParserError(
          errors.parser.unexpected,
          expectedMessage or util.toHex(bytes), util.toHex(actual)
        )
      end

      return actual
    end,

    tryConsume = function(self, bytes)
      if self:startsWith(bytes) then
        return self:expect(bytes)
      end

      return false
    end,

    readU8 = function(self)
      local byte, err = self:read(1)

      if not byte then
        return nil, err
      end

      return byte:byte()
    end,

    readVarint = function(self, disallowLeadingZero)
      return self:withContext("varint", function()
        local result = 0
        local first = true

        repeat
          local byte, err = self:rewinding():read(1)

          if not byte then
            return nil, err
          end

          byte = byte:byte()

          if first and disallowLeadingZero and byte == 0x80 then
            return nil, self:makeParserError(errors.parser.varintOverlong)
          end

          result = result << 7 | byte & 0x7f
          first = false
        until byte >> 7 == 0

        return result
      end)
    end,

    readInt = function(self, n, signed)
      local bytes, err = self:read(n)

      if not bytes then
        return nil, err
      end

      if n <= 8 then
        return ((">%s%d"):format(signed and "i" or "I", n):unpack(bytes))
      end

      return bitstring.fromBytes(bytes)
    end,
  }
}

function lib.makeBuffer(s)
  return setmetatable({
    __s = s,
    __pos = 1,
    __limit = {
      to = -1 >> 1,
      pos = 1,
      parent = nil,
    },
    __context = nil,
  }, meta)
end

return lib

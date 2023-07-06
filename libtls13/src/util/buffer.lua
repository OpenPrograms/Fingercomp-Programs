-- A byte buffer.
--
-- Stores chunks in a table to optimize allocation.

local util = require("tls13.util")

local lib = {}

local meta

meta = {
  __index = {
    append = function(self, chunk)
      if #chunk > 0 then
        table.insert(self.__chunks, chunk)
        self.__remaining = self.__remaining + #chunk
      end
    end,

    peek = function(self, n)
      return self:_read(n, false)
    end,

    consume = function(self, n)
      return self:_read(n, true)
    end,

    copy = function(self)
      return setmetatable({
        __chunks = util.copy(self.__chunks),
        __remaining = self.__remaining,
        __pos = self.__pos,
      }, meta)
    end,

    _read = function(self, n, consume)
      assert(n <= self.__remaining)

      local chunks = {}
      local consumed = 0
      local chunksConsumed = 0
      local lastChunkPos = 1

      for i, chunk in ipairs(self.__chunks) do
        local pos = 1

        if i == 1 and self.__pos > 1 then
          pos = self.__pos
        end

        if consumed + #chunk - pos + 1 > n then
          chunk = chunk:sub(pos, pos + n - consumed - 1)
          lastChunkPos = pos + #chunk
        else
          chunksConsumed = i

          if pos > 1 then
            chunk = chunk:sub(pos)
          end
        end

        table.insert(chunks, chunk)
        consumed = consumed + #chunk

        if consumed >= n then
          break
        end
      end

      assert(consumed == n)
      local result = table.concat(chunks)
      assert(#result == n)

      if consume then
        self.__pos = lastChunkPos
        util.removeShift(self.__chunks, chunksConsumed)
        self.__remaining = self.__remaining - consumed
      end

      return result
    end,

    remaining = function(self)
      return self.__remaining
    end,
  },
}

function lib.makeBuffer(initialContents)
  return setmetatable({
    __chunks = {initialContents},
    __remaining = initialContents and #initialContents or 0,
    __pos = 1,
  }, meta)
end

return lib

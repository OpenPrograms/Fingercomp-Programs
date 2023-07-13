-- A buffered I/O wrapper.

local buffer = require("tls13.util.buffer")

local lib = {}

local meta = {
  __index = {
    read = function(self, n)
      if not n and self.__buf:remaining() > 0 then
        return self:read(self.__buf:remaining())
      end

      while not n or n > self.__buf:remaining() do
        local chunk, err = self.__f:read(n and (n - self.__buf:remaining()))

        if not chunk then
          return nil, err
        elseif #chunk > 0 then
          n = n or #chunk
          self.__buf:append(chunk)
        end
      end

      return self.__buf:consume(n)
    end,

    write = function(self, data)
      local remaining = data

      while #remaining > 0 do
        local written, err = self.__f:write(remaining)

        if not written then
          return nil, err
        end

        remaining = remaining:sub(written + 1)
      end

      return #data
    end,

    close = function(self)
      self.__f:close()
    end,

    readUnpack = function(self, fmt)
      local size = string.packsize(fmt)
      local data, err = self:read(size)

      if not data then
        return nil, err
      end

      local result = table.pack(string.unpack(fmt, data))

      return table.unpack(result, 1, result.n - 1)
    end,

    inner = function(self)
      return self.__f
    end,
  },
}

function lib.wrap(f)
  return setmetatable({
    __f = f,
    __buf = buffer.makeBuffer(),
  }, meta)
end

return lib

local event = require("event")

local lib = {}

local POLL_TIMEOUT_SEC = 1

local meta = {
  __index = {
    read = function(self, count)
      return self:_read(count, true)
    end,

    write = function(self, data)
      return self.__sock.write(data)
    end,

    close = function(self)
      return self.__sock.close()
    end,

    _read = function(self, count, poll)
      local chunk, err = self.__sock.read(count)

      if not chunk then
        return nil, err
      elseif chunk == "" and poll then
        -- internet_ready is good but unreliable
        -- and having timeouts is just good practice
        event.pull(POLL_TIMEOUT_SEC, "internet_ready", nil, self.__sock.id())

        -- try fetching the data once more,
        -- but don't just get stuck here if we get nothing
        return self:_read(count, false)
      else
        return chunk
      end
    end,
  },
}

function lib.wrap(sock)
  return setmetatable({
    __sock = sock,
  }, meta)
end

return lib

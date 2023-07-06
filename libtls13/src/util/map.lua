-- Custom hashmaps.

local lib = {}

-- Makes a map that projects its keys to a primitive value for hash computation.
function lib.makeProjectionMap(projection, entries)
  local meta = {
    __index = function(self, k)
      local projectedKey = projection(k)

      return rawget(self, projectedKey)
    end,

    __newindex = function(self, k, v)
      local projectedKey = projection(k)

      rawset(self, projectedKey, v)
    end,
  }

  local map = setmetatable({}, meta)

  for k, v in pairs(entries or {}) do
    map[k] = v
  end

  return map
end

do
  local meta = {
    __newindex = function(self, k, v)
      assert(self[v] == nil, "value is already present in the map")

      rawset(self, k, v)
      rawset(self, v, k)
    end,
  }

  -- Makes a bidirectional map.
  function lib.makeBijectiveMap(entries)
    local result = setmetatable({}, meta)

    for k, v in pairs(entries or {}) do
      result[k] = v
    end

    return result
  end
end

return lib

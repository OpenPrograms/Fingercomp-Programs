-- OpenComputers-specific code.

local com = require("component")

local lib = {}

local function getDataCardTier(addr)
  local methods = com.methods(addr)

  if methods.ecdh ~= nil then
    return 3
  elseif methods.random ~= nil then
    return 2
  elseif methods.encode64 ~= nil then
    return 1
  else
    return 0
  end
end

function lib.getDataCard(tier)
  tier = tier or 3

  for addr in com.list("data", true) do
    if getDataCardTier(addr) >= tier then
      return com.proxy(addr)
    end
  end

  error(("T%d data card required"):format(tier))
end

return lib

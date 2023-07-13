-- OpenComputers random number generator.

local oc = require("tls13.oc")

local lib = {}

function lib.rng(count)
  return oc.getDataCard(2).random(count)
end

return lib

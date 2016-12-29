local charts = dofile("charts.lua")
local event = require("event")

local container = charts.Container()
local payload = charts.Histogram()
payload.max = 100
payload.min = -100
payload.level.value = 0
payload.level.y = .5
payload.align = charts.sides.RIGHT
payload.colorFunc = function(index, perc, value, self, container)
  return value >= 0 and 0xafff20 or 0x20afff
end
container.payload = payload

for i = 1, 400, 1 do
  table.insert(payload.values, math.sin(math.rad(i * 5)) * 100)
  container:draw()

  if event.pull(.05, "interrupted") then
    break
  end
end

local charts = require("charts")
local event = require("event")
local gpu = require("component").gpu

local container = charts.Container()
container.width, container.height = gpu.getViewport()

local payload = charts.Histogram()
payload.max = 1
payload.min = -1
payload.level.value = 0
payload.level.y = .5
payload.align = charts.sides.RIGHT
payload.colorFunc = function(index, perc, value, self, container)
  return value >= 0 and 0xafff20 or 0x20afff
end
container.payload = payload

for i = 1, math.huge, 1 do
  table.insert(payload.values, math.sin(math.rad(i * 3)))
  if #payload.values > container.width then
    table.remove(payload.values, 1)
  end
  container:draw()

  if event.pull(.05, "interrupted") then
    break
  end
end

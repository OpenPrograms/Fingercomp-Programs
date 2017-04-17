local charts = require("charts")
local event = require("event")
local gpu = require("component").gpu

local w, h = gpu.getViewport()

local container = charts.Container {
  width = w,
  height = h,
  payload = charts.Histogram {
    max = 1,
    min = -1,
    level = {
      value = 0,
      y = .5
    },
    align = charts.sides.RIGHT,
    colorFunc = function(index, perc, value, self, container)
      return value >= 0 and 0xafff20 or 0x20afff
    end
  }
}

for i = 1, math.huge, 1 do
  table.insert(container.payload.values, math.sin(math.rad(i * 3)))
  if #container.payload.values > container.width then
    table.remove(payload.values, 1)
  end
  container:draw()

  if event.pull(.05, "interrupted") then
    break
  end
end

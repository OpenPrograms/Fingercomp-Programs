local charts = require("charts")
local term = require("term")
local event = require("event")

local cleft = charts.Container {
  x = 1,
  y = 1,
  width = 50,
  height = 2,
  payload = charts.ProgressBar {
    direction = charts.sides.LEFT,
    value = 0,
    colorFunc = function(_, perc)
      if perc >= .9 then
        return 0x20afff
      elseif perc >= .75 then
        return 0x20ff20
      elseif perc >= .5 then
        return 0xafff20
      elseif perc >= .25 then
        return 0xffff20
      elseif perc >= .1 then
        return 0xffaf20
      else
        return 0xff2020
      end
    end
  }
}

local cright = charts.Container {
  x = 1,
  y = 4,
  width = 50,
  height = 2,
  payload = charts.ProgressBar {
    direction = charts.sides.RIGHT,
    value = 0,
    colorFunc = cleft.payload.colorFunc
  }
}

local ctop = charts.Container {
  x = 55,
  y = 1,
  width = 2,
  height = 20,
  payload = charts.ProgressBar {
    direction = charts.sides.TOP,
    value = 0,
    colorFunc = cleft.payload.colorFunc
  }
}

local cbottom = charts.Container {
  x = 59,
  y = 1,
  width = 2,
  height = 20,
  payload = charts.ProgressBar {
    direction = charts.sides.BOTTOM,
    value = 0,
    colorFunc = cleft.payload.colorFunc
  }
}

for i = 0, 100, 1 do
  term.clear()
  cleft.gpu.set(5, 10, "Value: " .. ("%.2f"):format(i / 100) .. " [" .. ("%3d"):format(i) .. "%]")
  cleft.gpu.set(5, 11, "Max:   " .. pleft.min)
  cleft.gpu.set(5, 12, "Min:   " .. pleft.max)

  cleft.payload.value, cright.payload.value, ctop.payload.value, cbottom.payload.value = i / 100, i / 100, i / 100, i / 100

  cleft:draw()
  ctop:draw()
  cright:draw()
  cbottom:draw()

  if event.pull(0.05, "interrupted") then
    term.clear()
    os.exit()
  end
end

event.pull("interrupted")
term.clear()

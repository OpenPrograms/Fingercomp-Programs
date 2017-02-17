local charts = require("charts")
local term = require("term")
local event = require("event")

local cleft = charts.Container()
cleft.x, cleft.y, cleft.width, cleft.height = 1, 1, 50, 2
local pleft = charts.ProgressBar()
pleft.direction = charts.sides.LEFT
pleft.value = 0
pleft.colorFunc = function(_, perc)
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
cleft.payload = pleft

local cright = charts.Container()
cright.x, cright.y, cright.width, cright.height = 1, 4, 50, 2
local pright = charts.ProgressBar()
pright.direction = charts.sides.RIGHT
pright.value = 0
pright.colorFunc = pleft.colorFunc
cright.payload = pright

local ctop = charts.Container()
ctop.x, ctop.y, ctop.width, ctop.height = 55, 1, 2, 20
local ptop = charts.ProgressBar()
ptop.direction = charts.sides.TOP
ptop.value = 0
ptop.colorFunc = pleft.colorFunc
ctop.payload = ptop

local cbottom = charts.Container()
cbottom.x, cbottom.y, cbottom.width, cbottom.height = 59, 1, 2, 20
local pbottom = charts.ProgressBar()
pbottom.direction = charts.sides.BOTTOM
pbottom.value = 0
pbottom.colorFunc = pleft.colorFunc
cbottom.payload = pbottom

for i = 0, 100, 1 do
  term.clear()
  cleft.gpu.set(5, 10, "Value: " .. ("%.2f"):format(i / 100) .. " [" .. ("%3d"):format(i) .. "%]")
  cleft.gpu.set(5, 11, "Max:   " .. pleft.min)
  cleft.gpu.set(5, 12, "Min:   " .. pleft.max)

  pleft.value, pright.value, ptop.value, pbottom.value = i / 100, i / 100, i / 100, i / 100

  cleft:draw()
  ctop:draw()
  cright:draw()
  cbottom:draw()

  if event.pull(0.05, "interrupted") then
    term.clear()
    break
  end
end

event.pull("interrupted")
term.clear()

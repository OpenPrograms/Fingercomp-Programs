-- XX  XX  XX  XX 2
--                   Height
-- XX  XX  XX  XX 1
--    2       1<>
--      Width

local W, H = 7, 11
local INTERVAL = 30

local com = require("component")
local robot = require("robot")
local term = require("term")

local magnet = com.tractor_beam

local INV = robot.inventorySize()

local wrappers = {
  rpt = function(f, to)
    to = to or 1
    return function(...)
      while not f(...) == true do
        os.sleep(to)
      end
      os.sleep(0)
    end
  end,
  detect = function(f, to)
    to = to or 1
    return function(...)
      while true do
        local s, rsn = f(...)
        if s then return true end
        if rsn == "entity" then
          robot.swing()
        elseif rsn == "air" then
          return true
        elseif rsn == "nothing selected" then
          return false
        else
          os.sleep(to)
        end
      end
    end
  end
}

local r = {
  fwd = wrappers.detect(robot.forward),
  back = wrappers.rpt(robot.back),
  left = wrappers.rpt(robot.turnLeft),
  right = wrappers.rpt(robot.turnRight),
  around = wrappers.rpt(robot.turnAround),
  up = wrappers.rpt(robot.up),
  down = wrappers.rpt(robot.down),
  suck = function()
    while magnet.suck() do
      os.sleep(.05)
    end
  end,
  swing = wrappers.detect(robot.swing),
  place = wrappers.detect(robot.place)
}

local function row()
  r.right()
  for i = 1, H, 1 do
    r.fwd()
    r.left()
    if robot.compare() and robot.durability() and robot.durability() > .1 then
      robot.select(INV)
      r.swing()
    end
    if not robot.detect() and robot.count(INV) > 1 then
      robot.select(INV)
      r.place()
    end
    robot.select(INV - 1)
    r.around()
    if robot.compare() and robot.durability() and robot.durability() > .1 then
      robot.select(INV)
      r.swing()
    end
    r.suck()
    if not robot.detect() and robot.count(INV) > 1 then
      robot.select(INV)
      r.place()
    end
    robot.select(INV - 1)
    r.left()
    if i ~= H then
      r.fwd()
    end
  end
  for i = 1, H, 1 do
    r.back()
    if i ~= H then
      r.back()
    end
  end
end

local function dropAll()
  for i = 1, INV - 2, 1 do
    if robot.count(i) > 0 then
      robot.select(i)
      robot.drop()
    end
  end
end

local function field()
  robot.select(INV - 1)
  for i = 1, W, 1 do
    r.fwd()
    row()
    if i ~= W then
      r.left()
      for fw = 1, 3, 1 do
        r.fwd()
      end
    end
  end
  r.right()
  for i = 1, W - 1, 1 do
    for fw = 1, 4 do
      r.fwd()
    end
  end
  r.fwd()
  dropAll()
  r.around()
end

while true do
  local x, y = term.getCursor()
  term.clearLine(y)
  term.setCursor(x, y)
  io.write("Running")
  field()
  for i = 0, INTERVAL, 1 do
    term.setCursor(x, y)
    term.clearLine(y)
    io.write("Sleep: " .. i .. " out of " .. INTERVAL)
    os.sleep(1)
  end
  os.sleep(0)
  term.setCursor(x, y)
end

-- vim: expandtab tabstop=2 shiftwidth=2 smartindent :

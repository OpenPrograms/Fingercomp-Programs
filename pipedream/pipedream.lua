local event = require("event")
local term = require("term")

local gpu = require("component").gpu

local width, height = gpu.getResolution()
height = height * 2

local minLen, maxLen = 100, 200

local pipes = {}
local sides = {
  top = 1,
  left = 2,
  bottom = 3,
  right = 4,
  "top",
  "left",
  "bottom",
  "right"
}
local char = "▀"

local turn = 5

local oldFg, oldBg = gpu.getForeground(), gpu.getBackground()
gpu.fill(1, 1, width, height / 2, " ")

local spawnInterval = 500
local lifeTime = 600
local clearInterval = 2500

local i = 0
while true do
  if i % spawnInterval == 0 then
    local x, y
    local side = math.random(1, 4)  -- choose one of 4 sides
    local direction
    if side == sides.top then
      x, y = math.random(1, width), 1
      direction = sides.bottom
    elseif side == sides.left then
      x, y = 1, math.random(1, height)
      direction = sides.right
    elseif side == sides.bottom then
      x, y = math.random(1, width), height
      direction = sides.top
    elseif side == sides.right then
      x, y = width, math.random(1, height)
      direction = sides.left
    end
    local length = math.random(minLen, maxLen)
    local r, g, b = 0, 0, 0
    while r < 127 and g < 127 and b < 127 do
      r, g, b = math.random(0, 255), math.random(0, 255), math.random(0, 255)
    end
    local color = r * 0x10000 + g * 0x100 + b
    local pipe = {
      x = x,
      y = y,
      length = length,
      dir = direction,
      color = color,
      life = lifeTime
    }
    table.insert(pipes, pipe)
  end

  for n = #pipes, 1, -1 do
    local pipe = pipes[n]
    if pipe.life == 0 then
      table.remove(pipes, n)
    else
      local c, fg, bg = gpu.get(pipe.x, 1 + math.floor((pipe.y - 1) / 2))
      if c ~= char then
        fg = oldBg
        bg = oldBg
      end
      local part = (pipe.y - 1) % 2
      local sBg, sFG
      if part == 0 then
        sFg = pipe.color
        sBg = bg
      else
        sFg = fg
        sBg = pipe.color
      end

      if gpu.getForeground() ~= sFg then
        gpu.setForeground(sFg)
      end
      if gpu.getBackground() ~= sBg then
        gpu.setBackground(sBg)
      end

      gpu.set(pipe.x, 1 + math.floor((pipe.y - 1) / 2), char)


      local dir = pipe.dir

      local shouldTurn = math.random(1, 100) <= turn
      local remains = {
        pipe.y - 2,
        pipe.x - 2,
        height - pipe.y - 1,
        width - pipe.x - 1
      }

      if remains[dir] == 0 then
        shouldTurn = true
      end

      if shouldTurn then
        local options = {dir - 1, dir + 1}
        if options[1] == 0 then
          options[1] = 4
        end
        if options[1] == 5 then
          options[1] = 1
        end
        if options[2] == 0 then
          options[2] = 4
        end
        if options[2] == 5 then
          options[2] = 1
        end

        if remains[options[2]] < 1 then
          table.remove(options, 2)
        end
        if remains[options[1]] < 1 then
          table.remove(options, 1)
        end

        dir = options[math.random(1, #options)]
      end

      pipe.dir = dir
      if pipe.dir == sides.top then
        pipe.y = pipe.y - 1
      elseif pipe.dir == sides.left then
        pipe.x = pipe.x - 1
      elseif pipe.dir == sides.right then
        pipe.x = pipe.x + 1
      elseif pipe.dir == sides.bottom then
        pipe.y = pipe.y + 1
      end
      pipe.life = pipe.life - 1
    end
  end
  i = i + 1
  if i >= clearInterval then
    if event.pull(2, "interrupted") then
      break
    end
    gpu.setBackground(0x000000)
    gpu.setForeground(0xffffff)
    gpu.fill(1, 1, width, height / 2, " ")
    i = 0
    pipes = {}
  else
    if event.pull(.05, "interrupted") then
      break
    end
  end
end

gpu.setForeground(oldFg)
gpu.setBackground(oldBg)

gpu.fill(1, 1, width, height / 2, " ")

term.setCursor(1, 1)

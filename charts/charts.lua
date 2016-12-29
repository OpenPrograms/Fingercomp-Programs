local component = require("component")

local sides = {
  TOP = 1,
  BOTTOM = 2,
  LEFT = 3,
  RIGHT = 4,
  "TOP",
  "BOTTOM",
  "LEFT",
  "RIGHT"
}

local Histogram

do
  local characters = {" ", "▁", "▂", "▃", "▄", "▅", "▆", "▇", "█"}
  local meta = {}
  meta.__index = meta

  local function calcHeight(height, perc)
    return math.floor(perc * height * 8)
  end

  local function getBarChars(height, halfHeight, totalHeight)
    if height < 0 then
      height = -height
      local spaces = math.floor(height / 8)
      local part = characters[8 - (height - spaces * 8) + 1]
      if spaces * 8 == height then
        part = ""
      end
      local blocks = totalHeight - halfHeight
      return characters[9]:rep(blocks) .. characters[1]:rep(spaces) .. part
    end
    local blocks = math.floor(height / 8)
    local part = characters[height - blocks * 8 + 1]
    if blocks * 8 == height then
      part = ""
    end
    local spaces = halfHeight - blocks - (part ~= "" and 1 or 0)
    return characters[1]:rep(spaces) .. part .. characters[9]:rep(blocks)
  end

  local function getMinMax(tbl)
    local max = -math.huge
    local min = math.huge
    for k, v in pairs(tbl) do
      if v > max then
        max = v
      end
      if v < min then
        min = v
      end
    end
    return max
  end

  function meta:draw(container)
    if self.max == self.min and self.max == 0 then
      error("min and max are both 0!")
    end
    local loopStart, loopEnd = 1, container.width
    if self.align == sides.RIGHT then
      loopEnd = #self.values
      loopStart = loopEnd - container.width + 1
    end
    local max = self.max - self.min
    local min = 0
    local bar = 1

    local levelY = self.level.y
    if levelY > 0 and levelY < 1 then
      levelY = levelY * container.height
    elseif levelY < 0 then
      levelY = container.height + levelY + 1
    end
    levelY = math.floor(levelY)
    if levelY > container.height then
      levelY = container.height
    end

    local levelV = self.level.value or self.min
    if levelV < self.min or levelV > self.max then
      error("invalid level value set!")
    end

    for i = loopStart, loopEnd do
      local value = self.values[i] or levelV
      if value < self.min or value > self.max then
        error("incorrect min/max values: min = " .. min .. ", max = " .. max .. ", v = " .. value)
      end
      local v = value - levelV
      local halfH = v < 0 and levelY or container.height - levelY

      local perc
      if v < 0 then
        perc = (levelV + value) / (levelV - self.min)
      else
        perc = (value - levelV) / (self.max - levelV)
      end
      if v == 0 and max == 0 then
        perc = 1
      end

      local height = calcHeight(halfH, perc)
      local chars = getBarChars(height, halfH, container.height)

      local fg, bg = self.colorFunc(i, perc, value, self, container)
      fg = fg or container.fg
      bg = bg or container.bg

      if v < 0 then
        fg, bg = bg, fg
      end

      if container.gpu.getForeground() ~= fg then
        container.gpu.setForeground(fg)
      end

      if container.gpu.getBackground() ~= bg then
        container.gpu.setBackground(bg)
      end

      container.gpu.set(container:getX() + bar - 1,
                        container:getY(),
                        chars,
                        true)
      bar = bar + 1
    end
  end

  Histogram = function()
    local obj = {
      values = {},
      align = sides.LEFT,
      colorFunc = function()
        return 0xffffff
      end,
      min = 0,
      max = 1,
      level = {
        y = 0,
        value = nil
      }
    }
    return setmetatable(obj, meta)
  end
end

local Container
do
  local meta = {}
  meta.__index = meta

  function meta:draw()
    if self.payload then
      local fg = self.gpu.getForeground()
      local bg = self.gpu.getBackground()
      if fg ~= self.fg then
        self.gpu.setForeground(self.fg)
      end
      if bg ~= self.bg then
        self.gpu.setBackground(self.bg)
      end

      self.gpu.fill(self.x, self.y, self.width, self.height, " ")
      self.payload:draw(self)

      if self.gpu.getForeground() ~= fg then
        self.gpu.setForeground(fg)
      end
      if self.gpu.getBackground() ~= bg then
        self.gpu.setBackground(bg)
      end
    end
  end

  function meta:getX()
    return self.x + self.payloadX - 1
  end

  function meta:getY()
    return self.y + self.payloadY - 1
  end

  Container = function()
    local obj = {
      gpu = component.gpu,
      fg = 0xffffff,
      bg = 0x000000,
      x = 1,
      y = 1,
      payloadX = 1,
      payloadY = 1,
      width = 80,
      height = 25,
      payload = nil
    }

    return setmetatable(obj, meta)
  end
end

return {
  sides = sides,
  Container = Container,
  Histogram = Histogram
}

local com = require("component")
local event = require("event")

local charts = require("charts")

local mfsu = com.mfsu
local gpu = com.gpu

local w, h = gpu.getViewport()

local function getColor(_, perc)
  if perc > .95 then
    return 0x6699FF
  elseif perc > .80 then
    return 0x33CC33
  elseif perc > .50 then
    return 0xFFFF33
  elseif perc > .25 then
    return 0xFFCC33
  elseif perc > .10 then
    return 0xFF3333
  else
    return 0x663300
  end
end

local function getDeltaColor(_, perc)
  return perc > 0 and 0x33CC33 or 0xFF3333
end

local hist = {
  hist10m = charts.Container {
    x = 2,
    y = 5,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = mfsu.getEUCapacity(),
      align = charts.sides.RIGHT,
      colorFunc = getColor
    },
    update = 600,
    timer = 0
  },

  hist1m = charts.Container {
    x = 2,
    y = 16,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = mfsu.getEUCapacity(),
      align = charts.sides.RIGHT,
      colorFunc = getColor
    },
    update = 60,
    timer = 0
  },

  hist30s = charts.Container {
    x = 43,
    y = 5,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = mfsu.getEUCapacity(),
      align = charts.sides.RIGHT,
      colorFunc = getColor
    },
    update = 30,
    timer = 0
  },

  hist1s = charts.Container {
    x = 43,
    y = 16,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = mfsu.getEUCapacity(),
      align = charts.sides.RIGHT,
      colorFunc = getColor
    },
    update = 1,
    timer = 0
  }
}

local histDelta = {
  hist10m = charts.Container {
    x = 21,
    y = 5,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = 1,
      min = -1,
      align = charts.sides.RIGHT,
      colorFunc = getDeltaColor,
      level = {
        y = 0.5,
        value = 0
      }
    },
    update = 600,
    timer = 0
  },

  hist1m = charts.Container {
    x = 21,
    y = 16,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = 1,
      min = -1,
      align = charts.sides.RIGHT,
      colorFunc = getDeltaColor,
      level = {
        y = 0.5,
        value = 0
      }
    },
    update = 60,
    timer = 0
  },

  hist30s = charts.Container {
    x = 62,
    y = 5,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = 1,
      min = -1,
      align = charts.sides.RIGHT,
      colorFunc = getDeltaColor,
      level = {
        y = 0.5,
        value = 0
      }
    },
    update = 30,
    timer = 0
  },

  hist1s = charts.Container {
    x = 62,
    y = 16,
    width = 18,
    height = 9,
    bg = 0x333333,
    payload = charts.Histogram {
      max = 1,
      min = -1,
      align = charts.sides.RIGHT,
      colorFunc = getDeltaColor,
      level = {
        y = 0.5,
        value = 0
      }
    },
    update = 1,
    timer = 0
  }
}

local progress = charts.Container {
  x = 2,
  y = 3,
  width = w - 2,
  height = 1,
  bg = 0x333333,
  payload = charts.ProgressBar {
    max = mfsu.getEUCapacity(),
    colorFunc = getColor
  }
}

gpu.fill(1, 1, w, h, " ")
gpu.set(2,  14, " 10m")
gpu.set(2,  25, " 1m")
gpu.set(42, 14, " 30s")
gpu.set(42, 25, " 1s")

local maxDelta = 1
local minDelta = 0
local lastValue = mfsu.getEUStored()

while not event.pull(1, "interrupted") do
  local stored, capacity = mfsu.getEUStored(), mfsu.getEUCapacity()
  local delta = stored - lastValue
  local redraw = true
  progress.payload.value = stored

  for k, histogram in pairs(hist) do
    histogram.timer = histogram.timer - 1
    if histogram.timer <= 0 then
      table.insert(histogram.payload.values, stored)
      if #histogram.payload.values > histogram.width then
        table.remove(histogram.payload.values, 1)
      end
      histogram.timer = histogram.update
      histogram:draw()
    end
  end

  local prev = {maxDelta, minDelta}
  for k, histogram in pairs(histDelta) do
    histogram.timer = histogram.timer - 1
    if histogram.timer <= 0 then
      table.insert(histogram.payload.values, delta)
      if #histogram.payload.values > histogram.width then
        table.remove(histogram.payload.values, 1)
      end
    end
    for _, v in pairs(histogram.payload.values) do
      maxDelta = math.max(maxDelta or v, v)
      minDelta = math.min(minDelta or v, v)
    end
  end

  gpu.fill(2, 1, w, 2, " ")
  gpu.set(2, 1, ("%+18d EU   min: %+18d EU  max: %+18d EU"):format(delta, minDelta, maxDelta))
  gpu.set(2, 2,
          ("%6.2f%% %31d EU  %31d EU"):format(stored / capacity * 100,
                                              stored, capacity))

  progress:draw()

  lastValue = stored

  local range = math.max(math.abs(minDelta), maxDelta)

  for k, histogram in pairs(histDelta) do
    histogram.payload.min = -range
    histogram.payload.max = range
    if histogram.timer <= 0 or redraw then
      histogram:draw()
    end
    if histogram.timer <= 0 then
      histogram.timer = histogram.update
    end
  end
end

gpu.fill(1, 1, gpu.getViewport(), select(2, gpu.getViewport()), " ")

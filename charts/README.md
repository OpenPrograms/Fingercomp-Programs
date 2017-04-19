Available for downloading on the [Hel repository](https://hel.fomalhaut.me/#packages/charts).

### Contents
* `Container`
* `Histogram`
* `ProgressBar`

### Usage
#### `Container`
Container contains a chart. It provides some common options like fg color, bg color, width, height, GPU to use, etc.

##### Attributes
* `Container.gpu` is the proxy to GPU to use.
* `Container.fg` is the default foreground color.
* `Container.bg` is the default bakground color.
* `Container.x` and `Container.y` define the top-left point of the container.
* `Container.payloadX` and `Container.payloadY` define the top-left point of the payload output area (relative to the container).
* `Container.width` and `Container.height` define the dimension of the payload output area.
* `Container.payload` is the chosen chart object.

##### Methods
* `Container:draw()` draws the chart. Restores the colors when it's done.

#### `Histogram`
You can learn what histogram is [here](https://en.wikipedia.org/wiki/Histogram).

The width of a histogram bar is 1 symbol.

##### Attributes
* `Histogram.values` is the table of numeric values.
* `Histogram.align` defines the alignment of the chart.
* `Histogram.colorFunc` is the function that returns fg and bg colors. If one of the values is missing, the container's values will be used instead. The function is called with the following arguments:
  * Item index
  * Normalized value (0 to 1).
  * The value itself.
  * The histogram object.
  * The container object.
* `Histogram.min` defines the value at the bottom. All histogram values must be greater than (or equal to) this value.
* `Histogram.max` defines the value at the top. All histogram values must be less than (or equal to) this value.
* `Histogram.level.y` sets the y coordinate of the histogram level (0 is default).
* `Histogram.level.value` sets the level value. Values under the level value will be drawn under the level, and vice versa.

#### `ProgressBar`
Progress bar, uh, is a bar that displays the progress. Well, you've probably already seen progress bars before so you don't need an explanation, right?

#### Attributes
* `ProgressBar.value` is a numeric value.
* `ProgressBar.max` is the maximum value of the progress bar.
* `ProgressBar.min` is the minumum value of the progress bar.
* `ProgressBar.direction` is the **direction** of the progress bar. This is where the end of the bar is.
* `ProgressBar.colorFunc` is a function that returns fg and bg colors. If one of the values is missing, the container's values will be used instead. The function is called with the following arguments:
  * Value.
  * Normalized value (0 to 1).
  * Progress bar object.
  * Container object.

### Sample code
```lua
local charts = require("charts")

local container = charts.Container()
local payload = charts.Histogram {
  max = 80,
  align = charts.sides.RIGHT,
  colorFunc = function(index, norm, value, self, container)
    return 0x20ff20
  end
}
container.payload = payload

for i = 1, 400, 1 do
  table.insert(payload.values, math.random(0, 80))
  container:draw()

  os.sleep(.05)
end
```

```lua
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
```

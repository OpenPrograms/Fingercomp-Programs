![Example](https://i.imgur.com/SCnOt85.png)

This library can draw charts, actually. Right now only histograms are supported but hopefully I'll add more in the future.

### Contents
* `Container`
* `Histogram`

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

### Sample code
```lua
local charts = require("charts")

local container = charts.Container()
local payload = charts.Histogram()
payload.max = 80
payload.align = charts.sides.RIGHT
payload.colorFunc = function(index, norm, value, self, container)
  return 0x20ff20
end
container.payload = payload

for i = 1, 400, 1 do
  table.insert(payload.values, math.random(0, 80))
  container:draw()

  os.sleep(.05)
end
```

local com = require("component")
local event = require("event")

local p = com.particle

local function spawn(pname, x, y, z, pvx, pvy, pvz)
  if type(pvx) == "number" then
    if type(pvy) == "number" and type(pvz) == "number" then
      return p.spawn(pname, x, y, z, pvx, pvy, pvz)
    else
      return p.spawn(pname, x, y, z, pvx)
    end
  else
    return p.spawn(pname, x, y, z)
  end
end

local function draw(image, pcoords, pname, pv, step, doubleHeight)
  pcoords = pcoords or {}
  local px, py, pz = table.unpack(pcoords)
  px = px or 0
  py = py or 0
  pz = pz or 0
  pname = pname or "flame"
  local pvx, pvy, pvz
  if type(pv) == "number" then
    pvx = pv
  elseif type(pv) == "table" then
    pvx, pvy, pvz = table.unpack(pv)
  end

  local x = 0
  for line in image:gmatch("[^\n]+") do
    x = x + step * 2
    local z = 0
    for c in line:gmatch(".") do
      z = z + step
      if c == "#" then
        for i = 1, 5, 1 do
          spawn(pname, x + px, py, z + pz, pvx, pvy, pvz)
          if doubleHeight then
            spawn(pname, x + px + step, py, z + pz, pvx, pvy, pvz)
          end
        end
      end
    end
  end
end

return draw

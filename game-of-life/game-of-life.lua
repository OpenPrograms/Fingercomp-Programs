local com = require("component")
local comp = require("computer")
local unicode = require("unicode")
local event = require("event")
local term = require("term")

local screen = com.screen
local gpu = com.gpu

local w, h = gpu.getResolution()

local cells = {}
local scsr = {}

local bw, bh = w, (h - 2) * 2

local pause = true
local firstUpd = true
local gen = 0
local updScsr = true
local cellHL = false

local blocks = {
  dl = 0x2596,
  dr = 0x2597,
  ul = 0x2598,
  ur = 0x259d,
  uldr = 0x259a,
  urdl = 0x259e,
  Ldl = 0x2599,
  Ldr = 0x259f,
  Lul = 0x259b,
  Lur = 0x259c,
  block = 0x2588,
  ulur = 0x2580,
  dldr = 0x2584,
  uldl = 0x258c,
  urdr = 0x2590
}

local speeds = {0.05, 0.1, 0.2, 0.25, 0.4, 0.5, 0.8, 1, 2, 3, 4, 5, 7, 10}
local speed = 2

screen.setPrecise(true)

for i = 1, bw, 1 do
  cells[i] = {}
  scsr[i] = {}
  for j = 1, bh, 1 do
    cells[i][j] = false
    scsr[i][j] = false
  end
end

for k, v in pairs(blocks) do
  blocks[k] = unicode.char(v)
end

local function copy(tbl)
  if type(tbl) ~= "table" then return tbl end
  local result = {}
  for k, v in pairs(tbl) do
    result[k] = copy(v)
  end
  return result
end

local function getSymbol(u, d)
  if u and d then
    return blocks.block
  elseif not u and d then
    return blocks.dldr
  elseif u and not d then
    return blocks.ulur
  elseif not u and not d then
    return " "
  end
end

local function getPixel(x, y)
  x = x % bw
  y = y % bh
  if x % bw == 0 then
    x = bw
  end if y % bh == 0 then
    y = bh
  end
  return cells[x][y]
end

local function getScsrPixel(x, y)
  if scsr[x] and scsr[x][y] ~= nil then
    return scsr[x][y]
  end
  return nil
end

local function getCell(x, y)
  y = y % 2 == 0 and y - 1 or y
  local gridColorUpper = x % 2 == 0 and 0x000000 or 0x1e1e1e
  local gridColorLower = x % 2 == 0 and 0x1e1e1e or 0x000000
  local sc = {}
  sc.u = {getPixel(x, y), getScsrPixel(x, y)}
  sc.d = {getPixel(x, y + 1), getScsrPixel(x, y + 1)}
  for k, v in pairs(sc) do
    if v[2] ~= nil then
      if v[1] and v[2] then
        sc[k][3] = 0xffffff
      elseif v[1] and v[2] == false then
        sc[k][3] = 0x800000
      elseif v[1] == false and v[2] then
        sc[k][3] = 0x008000
      elseif v[1] == false and v[2] == false then
        sc[k][3] = false
      end
    else
      sc[k][3] = v[1] and 0xffffff or false
    end
  end
  sc.u[3] = sc.u[3] or gridColorUpper
  sc.d[3] = sc.d[3] or gridColorLower
  return sc.u[3], sc.d[3]
end

local function neighbors(x, y)
  local nb = 0
  for i = x - 1, x + 1, 1 do
    for j = y - 1, y + 1, 1 do
      if not (i == x and j == y) then
        if getPixel(i, j) then
          nb = nb + 1
        end
      end
    end
  end
  return nb
end

local function rules(x, y)
  local nb = neighbors(x, y)
  local alive = getPixel(x, y) and nb == 2 or nb == 3
  return alive
end

local function updateField()
  local successor = {}
  for i = 1, bw, 1 do
    for j = 1, bh, 1 do
      successor[i] = successor[i] or {}
      local cell = rules(i, j)
      successor[i][j] = cell
    end
  end
  return successor
end

local function render()
  gpu.setBackground(0xffffff)
  gpu.setForeground(0x000000)
  gpu.fill(1, 1, w, 1, " ")
  gpu.fill(1, h, w, 1, " ")
  gpu.set(1, h, "[␣] Pause/Unpause [q] Quit [↵] Next gen [<] Slower [>] Faster")
  gpu.set(1, 1, "CONWAY'S GAME OF LIFE")
  gpu.set(w - #tostring(gen) - 1, h, "G" .. gen)
  gpu.set(w - 28, 1, "Upd rate " .. speeds[speed] .. "s")
  gpu.setForeground(0xffffff)
  if pause then
    gpu.setBackground(0x808000)
    gpu.set(w - 13, 1, " " .. unicode.char(0x23f8) .. " Paused    ")
  else
    gpu.setBackground(0x008000)
    gpu.set(w - 13, 1, " " .. unicode.char(0x25ba) .. " Simulation ")
  end
  for i = 1, bw, 1 do
    for j = 1, bh, 2 do
      local colorU, colorD = getCell(i, j)
      local pixel = {gpu.get(i, (j + 1) / 2 + 1)}
      if pixel[1] ~= blocks.ulur or pixel[2] ~= colorU or pixel[3] ~= colorD or firstUpd then
        if gpu.getForeground() ~= colorU then
          gpu.setForeground(colorU)
        end if gpu.getBackground() ~= colorD then
          gpu.setBackground(colorD)
        end
        gpu.set(i, (j + 1) / 2 + 1, blocks.ulur)
        if firstUpd then
          firstUpd = false
        end
      end
    end
  end
end

local function updBoard()
  if updScsr then
    cells = updateField()
    scsr = updateField()
    updScsr = false
  else
    cells = copy(scsr)
    scsr = updateField()
  end
end

local function onTouch(event, address, x, y, btn, user)
  if y > 1 and y < h and pause then
    cells[math.floor(x) + 1][math.floor(y * 2) - 1] = btn == 0
    scsr = updateField()
  end
end

local function onKey(...)
  data = {...}
  if data[3] == 32 then
    pause = not pause
  elseif data[4] == 16 then
    noExit = false
  elseif data[3] == 13 and pause then
    updBoard()
    gen = gen + 1
  elseif data[3] == 62 then
    local sp = speed - 1
    speed = sp == 0 and 1 or sp
  elseif data[3] == 60 then
    local sp = speed + 1
    speed = sp > #speeds and #speeds or sp
  end
end

event.listen("touch", onTouch)
event.listen("drag", onTouch)
event.listen("drop", onTouch)
event.listen("key_down", onKey)
local renderTimer = event.timer(0.05, render, math.huge)

noExit = true
while noExit do
  if not pause then
    updBoard()
    gen = gen + 1
  end
  os.sleep(speeds[speed])
end

event.ignore("touch", onTouch)
event.ignore("drag", onTouch)
event.ignore("drop", onTouch)
event.ignore("key_down", onKey)
event.cancel(renderTimer)

gpu.setForeground(0xffffff)
gpu.setBackground(0x000000)
gpu.fill(1, 1, w, h, " ")
screen.setPrecise(false)
term.setCursor(1, 1)

-- vim: expandtab tabstop=2 shiftwidth=2 autoindent :

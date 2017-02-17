local image = [[
####...###....#...#####
....#.#...#...#.......#
.###..#...#...#......#.
#.....#...#...#.....#..
#####..###....#....#...
]]

while 1 do
  local px, py, pz = -5, 4.8, -5
  local pname = "flame"
  local pvx, pvy, pvz = 0, 0, 0
  local step = .2
  local doubleHeight = false
  draw(image, {px, py, pz}, pname, {pvx, pvy, pvz}, step, doubleHeight)
  if event.pull(.05, "interrupted") then
    break
  end
end

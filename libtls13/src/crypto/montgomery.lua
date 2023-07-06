-- Montgomery multiplication in a residual ring modulo an odd m.
--
-- In essence, a port of [1] to Lua.
--
-- Ref:
-- - https://eprint.iacr.org/2011/239.pdf
-- - https://maths-people.anu.edu.au/~brent/pd/mca-cup-0.5.9.pdf
--
-- [1] https://github.com/rust-num/num-bigint/blob/14b6f73cf7662cda56c8eaebb779fc49b65d6928/src/bigint.rs

local util = require("tls13.util")

local lib = {}

local min = math.min
local max = math.max
local ult = math.ult
local nlz64 = util.nlz64

local function checkValid(x)
  assert(#x >= 1, "#x must be positive")

  for i = 1, #x, 1 do
    assert(
      x[i] >> 32 == 0,
      ("x[%d] = %08x %08x has garbage in high bits"):format(
        i, x[i] >> 32, x[i] & 0xffffffff
      )
    )
  end
end

local function resize(tbl, n, filler)
  for i = #tbl + 1, n, 1 do
    tbl[i] = filler
  end
end

local function fill(tbl, filler, start, count)
  start = start or 1
  local final = count and start + count - 1 or #tbl

  for i = start, final, 1 do
    tbl[i] = filler
  end
end

local function stripZeros(n)
  for i = #n, 2, -1 do
    if n[i] == 0 then
      n[i] = nil
    else
      break
    end
  end
end

local function cmp(x, y, m)
  local n = max(#x, #y)
  m = m or 0

  for i = n, 1, -1 do
    local lhs = x[i] or 0
    local rhs = y[i - m] or 0

    if lhs < rhs then
      return -1
    elseif lhs > rhs then
      return 1
    end
  end

  return 0
end

-- Computes -w⁻¹ mod 2³².
local function invMod(w)
  assert(w & 1 == 1, "w must be odd")

  local k0 = 2 - w
  local t = w - 1
  local i = 1

  repeat
    t = t * t
    k0 = k0 * (t + 1)
    i = i << 1
  until i == 32

  return -k0 & 0xffffffff
end

local function mulAddWordWordWord(x, y, c)
  local z = x * y + c

  return z >> 32, z & 0xffffffff
end

local function addWordWord(x, y, carry)
  local yc = (y + carry) & 0xffffffff
  local z = (x + yc) & 0xffffffff

  if z < x or yc < y then
    return 1, z
  else
    return 0, z
  end
end

local function subVecVec(z, m)
  local n = #m
  local borrow = 0

  for i = 1, n, 1 do
    local xi = z[n + i]
    local yi = m[i]

    local zi = (xi - yi - borrow) & 0xffffffff
    z[i] = zi
    borrow = (yi & ~xi | (yi | ~xi) & zi) >> 31
  end

  return borrow
end

local function subVecVecShifted(x, y, shiftWordCount)
  local borrow = 0

  for i = 1, #x, 1 do
    local xi = x[i]
    local yi = y[i - shiftWordCount] or 0
    local zi = (xi - yi - borrow) & 0xffffffff
    x[i] = zi
    borrow = (yi & ~xi | (yi | ~xi) & zi) >> 31
  end

  return borrow
end

local function addVecVecShifted(x, y, shiftWordCount)
  local carry = 0

  for i = 1, #x, 1 do
    local xi = x[i]
    local yi = y[i - shiftWordCount] or 0
    local zi = (xi + yi + carry) & 0xffffffff
    x[i] = zi
    carry = (xi & yi | (xi | yi) & ~zi) >> 31
  end

  return carry
end

local function mulVecWord(x, y)
  local z = {0}

  for i = 1, #x, 1 do
    local doubleWord = x[i] * y
    local zi = z[i] + (doubleWord & 0xffffffff)
    z[i] = zi & 0xffffffff
    z[i + 1] = (doubleWord >> 32) + (zi >> 32)
  end

  return z
end

local function add4x24(x3, x2, x1, x0, y3, y2, y1, y0)
  -- may consider 32+64 + 32+64 instead
  local carry = 0

  local z0 = (x0 + y0) & 0xffffff
  carry = (x0 & y0 | (x0 | y0) & ~z0) >> 23

  local z1 = (x1 + y1 + carry) & 0xffffff
  carry = (x1 & y1 | (x1 | y1) & ~z1) >> 23

  local z2 = (x2 + y2 + carry) & 0xffffff
  carry = (x2 & y2 | (x2 | y2) & ~z2) >> 23

  local z3 = (x3 + y3 + carry) & 0xffffff
  carry = (x3 & y3 | (x3 | y3) & ~z3) >> 23

  return z3, z2, z1, z0, carry
end

local function sub4x24(x3, x2, x1, x0, y3, y2, y1, y0)
  -- may consider 32+64 - 32+64 instead
  local borrow = 0

  local z0 = (x0 - y0) & 0xffffff
  borrow = (y0 & ~x0 | (y0 | ~x0) & z0) >> 23

  local z1 = (x1 - y1 - borrow) & 0xffffff
  borrow = (y1 & ~x1 | (y1 | ~x1) & z1) >> 23

  local z2 = (x2 - y2 - borrow) & 0xffffff
  borrow = (y2 & ~x2 | (y2 | ~x2) & z2) >> 23

  local z3 = (x3 - y3 - borrow) & 0xffffff
  borrow = (y3 & ~x3 | (y3 | ~x3) & z3) >> 23

  return z3, z2, z1, z0, borrow
end

local function add3x24(x2, x1, x0, y2, y1, y0)
  local xHi, xLo = x2 >> 16, x2 << 48 | x1 << 24 | x0
  local yHi, yLo = y2 >> 16, y2 << 48 | y1 << 24 | y0

  local zLo = xLo + yLo
  local carry = (xLo & yLo | (xLo | yLo) & ~zLo) >> 63

  local zHi = xHi + yHi + carry
  carry = (xHi & yHi | (xHi | yHi) & ~zHi) >> 7

  return
    (zHi << 16 | zLo >> 48) & 0xffffff,
    (zLo >> 24) & 0xffffff,
    zLo & 0xffffff,
    carry
end

local function sub3x24(x2, x1, x0, y2, y1, y0)
  local xHi, xLo = x2 >> 16, x2 << 48 | x1 << 24 | x0
  local yHi, yLo = y2 >> 16, y2 << 48 | y1 << 24 | y0

  local zLo = xLo - yLo
  local borrow = (yLo & ~xLo | (yLo | ~xLo) & zLo) >> 63

  local zHi = xHi - yHi - borrow
  borrow = (yHi & ~xHi | (yHi | ~xHi) & zHi) >> 7

  return
    (zHi << 16 | zLo >> 48) & 0xffffff,
    (zLo >> 24) & 0xffffff,
    zLo & 0xffffff,
    borrow
end

-- y must be normalized (have the 31st bit set)
local function divide64By32(hi, lo, y)
  assert(y >> 31 == 1, "y must be normalized")

  local x = hi << 32 | lo

  if x >> 63 == 0 then
    -- x as an i64 is non-negative, so the regular division works fine
    -- (should be the majority of cases)
    return x // y
  end

  -- there's no 64-by-32 unsigned division in lua, so we use 24-bit words
  -- the number of words:
  --   in normalized x: n + m = 4
  --   in normalized y: n = 2
  -- y1 >> 23 needs to be 1
  -- technically there's also z2, but it's always 0 because of the checks above
  local z1, z0 = 0, 0

  local x3 = x >> 56 -- non-zero before the comparison, now could be 0
  local x2 = (x >> 32) & 0xffffff
  local x1 = (x >> 8) & 0xffffff
  local x0 = (x << 16) & 0xffffff

  local y1 = y >> 8
  local y0 = (y << 16) & 0xffffff

  -- j = 1
  z1 = min((x3 << 24 | x2) // y1, 0xffffff)

  -- uses up to 56 bits, needs to be shifted by 16 + 24 bits
  local subtrahend, carry = z1 * y
  -- x3:x0 = x3:x0 - (subtrahend << 40)
  x3, x2, x1, x0, carry = sub4x24(
    x3, x2, x1, x0,
    subtrahend >> 32,
    (subtrahend >> 8) & 0xffffff,
    (subtrahend << 16) & 0xffffff,
    0
  )

  while carry ~= 0 do
    z1 = z1 - 1
    x3, x2, x1, x0, carry = add4x24(x3, x2, x1, x0, 0, y1, y0, 0)
    carry = carry - 1
  end

  assert(x3 == 0)

  -- j = 0
  z0 = min((x2 << 24 | x1) // y1, 0xffffff)

  subtrahend = z0 * y
  -- x2:x0 = x2:x0 - (subtrahend << 16)
  x2, x1, x0, carry = sub3x24(
    x2, x1, x0,
    subtrahend >> 32,
    (subtrahend >> 8) & 0xffffff,
    (subtrahend << 16) & 0xffffff
  )

  while carry ~= 0 do
    z0 = z0 - 1
    x2, x1, x0, carry = add3x24(x2, x1, x0, 0, y1, y0)
    carry = carry - 1
  end

  assert(x2 == 0)

  return z1 << 24 | z0
end

local function addMulVecVecWord(z, x, y, zStart)
  local carry = 0

  for i = 1, #x, 1 do
    local zHi, zLo = mulAddWordWordWord(x[i], y, z[zStart + i - 1])
    local c, zi = addWordWord(zLo, carry, 0)
    z[zStart + i - 1] = zi
    carry = c + zHi
  end

  return carry
end

local function montgomery(x, y, m, k)
  local n = max(#x, #y, #m)
  assert(#x == n and #y == n and #m == n, "arrays must have the same size")

  local z = {}
  resize(z, 2 * n, 0)

  local c = 0

  for i = 1, n, 1 do
    local c2 = addMulVecVecWord(z, x, y[i], i)
    local t = (z[i] * k) & 0xffffffff
    local c3 = addMulVecVecWord(z, m, t, i)
    local cx = (c + c2) & 0xffffffff
    local cy = (cx + c3) & 0xffffffff
    z[n + i] = cy

    if cx < c2 or cy < c3 then
      c = 1
    else
      c = 0
    end
  end

  if c == 0 then
    util.removeShift(z, n)
  else
    subVecVec(z, m)
    fill(z, nil, n + 1)
  end

  return z
end

local function shiftLeft(x, n)
  assert(n <= 32, "shift count is too large")

  local shiftedOut = x[#x] >> 32 - n

  for i = #x, 2, -1 do
    x[i] = (x[i] << n | x[i - 1] >> 32 - n) & 0xffffffff
  end

  x[1] = (x[1] << n) & 0xffffffff

  if shiftedOut ~= 0 then
    x[#x + 1] = shiftedOut
  end
end

local function shiftRight(x, n)
  assert(n <= 32, "shift count is too large")

  for i = 1, #x - 1, 1 do
    x[i] = (x[i] >> n | x[i + 1] << 32 - n) & 0xffffffff
  end

  local msw = x[#x] >> n

  if msw == 0 and #x > 1 then
    x[#x] = nil
  else
    x[#x] = msw
  end
end

local function modVecVec(x, y)
  stripZeros(x)
  stripZeros(y)
  assert(y[1] ~= 0, "division by zero")

  x = util.copy(x)

  if #x < #y then
    -- x < y ⇒ x % y = x
    return x
  end

  y = util.copy(y)

  local shiftCount = nlz64(y[#y]) - 32
  shiftLeft(x, shiftCount)
  shiftLeft(y, shiftCount)
  assert(y[#y] >> 31 == 1, "normalization failed")

  local m = #x - #y

  if cmp(x, y, m) >= 0 then
    subVecVecShifted(x, y, m)
  end

  -- the most significant word of y; used for quotient selection
  local yMsw = y[#y]

  for j = m - 1, 0, -1 do
    local qj = min(divide64By32(x[#y + j + 1], x[#y + j], yMsw), 0xffffffff)
    local subtrahend = mulVecWord(y, qj)
    local carry = subVecVecShifted(x, subtrahend, j)

    while carry ~= 0 do
      carry = addVecVecShifted(x, y, j) - 1
    end
  end

  -- x, shifted back, is the remainder
  shiftRight(x, shiftCount)
  stripZeros(x)

  return x
end

function lib.modPowOdd(x, y, m)
  assert(m[1] & 1 == 1, "the modulus must be odd")

  local mr = invMod(m[1])
  local x = util.copy(x)

  if #x > #m then
    x = modVecVec(x, m)
  end

  resize(x, #m, 0)

  local rr = {}
  resize(rr, 2 * #m, 0)
  rr[2 * #m + 1] = 1
  rr = modVecVec(rr, m)

  local one = {1}
  resize(one, #m, 0)

  local windowSize = 4
  local powers = {
    [0] = montgomery(one, rr, m, mr),
    [1] = montgomery(x, rr, m, mr),
  }

  for i = 2, (1 << windowSize) - 1, 1 do
    table.insert(powers, montgomery(powers[i - 1], powers[1], m, mr))
  end

  local z = powers[0]
  resize(z, #m, 0)
  local zz = {}
  resize(zz, #m, 0)

  for i = #y, 1, -1 do
    local yi = y[i]
    local j = 0

    repeat
      if i ~= #y or j ~= 0 then
        zz = montgomery(z, z, m, mr)
        z = montgomery(zz, zz, m, mr)
        zz = montgomery(z, z, m, mr)
        z = montgomery(zz, zz, m, mr)
      end

      zz = montgomery(z, powers[yi >> 32 - windowSize], m, mr)
      z, zz = zz, z
      yi = (yi << windowSize) & 0xffffffff
      j = j + windowSize
    until j == 32
  end

  zz = montgomery(z, one, m, mr)

  if cmp(zz, m) >= 0 then
    table.move(zz, #m + 1, #m * 2, 1)
    subVecVec(zz, m)
    fill(zz, nil, #m + 1)

    if cmp(zz, m) >= 0 then
      zz = modVecVec(zz, m)
    end
  end

  stripZeros(zz)

  return zz
end

function lib.fromHex(s)
  local result = {}

  for i = 8, #s + 7, 8 do
    local wordHex = s:sub(-i, -i + 7)
    table.insert(result, tonumber(wordHex, 16))
  end

  stripZeros(result)

  return result
end

function lib.toHex(x, sep)
  local result = {("%x"):format(x[#x])}

  for i = #x - 1, 1, -1 do
    table.insert(result, ("%08x"):format(x[i]))
  end

  return table.concat(result, sep and " " or "")
end

function lib.fromBytes(s)
  local result = {}

  for i = 4, #s + 3, 4 do
    local word = s:sub(-i, -i + 3)

    if #word ~= 4 then
      -- unpack returns two values, the parentheses retain only the first
      table.insert(result, ((">I" .. #word):unpack(word)))
    else
      table.insert(result, ((">I4"):unpack(word)))
    end
  end

  if #result == 0 then
    result[1] = 0
  end

  stripZeros(result)

  return result
end

function lib.toBytes(x, n)
  stripZeros(x)

  local parts = {}

  for i = 1, #x, 1 do
    parts[i] = (">I4"):pack(x[i] & 0xffffffff)
  end

  if not n then
    n = #parts * 4

    if x[#x] & 0xffffffff <= 0xff then
      n = n - 3
    elseif x[#x] & 0xffffffff <= 0xffff then
      n = n - 2
    elseif x[#x] & 0xffffffff <= 0xffffff then
      n = n - 1
    end
  end

  -- padding
  for i = #x + 1, util.idivCeil(n, 4), 1 do
    parts[i] = "\0\0\0\0"
  end

  util.reverse(parts)
  local concatenated = table.concat(parts)

  for i = 1, #concatenated - n, 1 do
    if concatenated:byte(i) ~= 0 then
      -- chopping off to fit n bytes would eat a non-padding byte
      return nil
    end
  end

  return concatenated:sub(-n)
end

lib.cmp = cmp
lib.shiftLeft = shiftLeft
lib.shiftRight = shiftRight

function lib.bitCount(x)
  stripZeros(x)

  local fullWordBits = (#x - 1) * 32
  local lastWordBits = util.lastLeadingZero(x[#x])

  return fullWordBits + lastWordBits
end

lib.__internal = {
  modVecVec = modVecVec,
  divide64By32 = divide64By32,
  subVecVecShifted = subVecVecShifted,
}

return lib

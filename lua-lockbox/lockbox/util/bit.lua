local ok, e
if not ok then
	ok, e = pcall(require, "bit") -- the LuaJIT one ?
end
if not ok then
	ok, e = pcall(require, "bit32") -- Lua 5.2
end
if not ok then
	ok, e = pcall(require, "bit.numberlua") -- for Lua 5.1, https://github.com/tst2005/lua-bit-numberlua/
end
if not ok then
	error("no bitwise support found", 2)
end

-- Workaround to support Lua 5.2 bit32 API with the LuaJIT bit one
if e.rol and not e.lrotate then
	e.lrotate = e.rol
end
if e.ror and not e.rrotate then
	e.rrotate = e.ror
end

-- fix of OpenComputers' broken bit32 library
if _VERSION:find("5.3") and _OSVERSION then
  e.rrotate = function(x, disp)
    if disp == 0 then
      return x
    elseif disp < 0 then
      return e.lrotate(x, -disp)
    else
      disp = e.band(disp, 31)
      x = e.band(x, 0xffffffff)
      return e.band(e.bor(e.rshift(x, disp), e.lshift(x, (32 - disp))), 0xffffffff)
    end
  end

  e.lrotate = function(x, disp)
    if disp == 0 then
      return x
    elseif disp < 0 then
      return e.rrotate(x, -disp)
    else
      disp = e.band(disp, 31)
      x = e.band(x, 0xffffffff)
      return e.band(e.bor(e.lshift(x, disp), r.shift(x, (32 - disp))), 0xffffffff)
    end
  end
end

return e

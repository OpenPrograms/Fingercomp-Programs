local function parseCSV(s)
  result = {}
  row = {}
  cell = ""
  quoted = false
  prevQuote = false

  for i = 1, #s, 1 do
    c = s:sub(i, i)
    if quoted then
      if c == '"' then
        prevQuote = true
        quoted = false
      else
        cell = cell .. c
      end
    else
      if c == '"' then
        if #cell == 0 then
          quoted = true
        else
          if prevQuote then
            cell = cell .. '"'
            quoted = true
            prevQuote = false
          else
            return false
          end
        end
      elseif c == "," then
        table.insert(row, cell)
        cell = ""
        prevQuote = false
      elseif c == "\n" then
        table.insert(row, cell)
        cell = ""
        table.insert(result, row)
        row = {}
        prevQuote = false
      else
        if prevQuote then
          return false
        end
        cell = cell .. c
      end
    end
  end

  if #cell ~= 0 then
    if quoted then
      return false
    end
    table.insert(row, cell)
    table.insert(result, row)
  end

  return result
end

local function test()
  local p = function(s)
    print(require("serialization").serialize(s))
  end

  p(parseCSV(
[[
aaa,bbb,ccc,ddd
eee,fff,ggg,hhh
]]
  ))
  p(parseCSV(
[[
aaa,bbb,ccc,ddd
eee,fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,ccc,"ddd
eee",fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,c"cc,ddd
eee,fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,"ccc,ddd
eee,fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,"cc"c,ddd
eee,fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,"cc""c,ddd
eee,fff,ggg,hhh]]
  ))
  p(parseCSV(
[[
aaa,bbb,"cc""c",ddd
eee,fff,ggg,hhh]]
  ))
end

return parseCSV

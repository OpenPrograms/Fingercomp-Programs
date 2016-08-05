local com = require("component")

local tls = require("tls")

local inet = com.internet

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local tokenChars = "!#$%%&'*+-.^_`|~0-9A-Za-z"
local visibleChars = "\x20-\x7e"
local unreservedChars = "A-Za-z0-9-._~"

local function encode(str, allowed)
  allowed = allowed or {}
  if type(allowed) ~= "table" then
    allowed = {}
  end
  return str:gsub("[A-Za-z0-9-_.~]", function(c)
    if isin(allowed, c) then return c end
    return "%" .. ("%02X"):format(c:byte())
  end)
end

local function trainCase(str)
  local parts = {}
  for part in str:gmatch("[^-]+") do
    parts[#parts+1] = part:sub(1, 1):upper() .. part:sub(2, -1)
  end
  return table.concat(parts)
end

local function read(s, l)
  local result = s[0]:sub(1, l)
  s[0] = s[0]:sub(l + 1, -1)
  return result
end

local function read2crlf(pstr)
  local data = ""
  while pstr[0]:sub(1, 2) ~= "\r\n" do
    data = data .. read(pstr, 1)
  end
  data = data .. read(pstr, 2)
  return data
end

local function newHTTPRequest(url, kwargs, ...)
  check(url, "url", "string")
  if type(kwargs) ~= "table" then
    local args = {...}
    kwargs = {body = kwargs, headers = args[1], ...}
  end
  if not url:match("^https?://") then
    url = "http://" .. url
  end
  if url:match("^https?://.+[^/]$") then
    url = url .. "/"
  end
  local protocol, domain, path = url:match("^(https?)://(.-)(/.*)$")
  local body, headers, method = kwargs.body, kwargs.headers, kwargs.method
  local closeConnection = kwargs.closeConnection
  check(headers, "headers", "table", "nil")
  check(method, "method", "string", "nil")
  check(body, "body", "string", "nil")
  -- get port if present
  local port
  if domain:find(":") then
    domain, port = domain:match("^(.+):(.*)$")
    port = tonumber(port)
  end
  if port and (port < 1 or port > 65535) then
    error("bad port")
  end
  -- domain sanity checks
  local isIP = (function()
    local parts = {}
    for subdomain in domain:gmatch("[^.]") do
      -- reverse the order of table, will store something like this:
      -- com, google, www
      table.insert(parts, 1, subdomain)
    end
    -- there must be tld and second level domain
    assert(#parts > 1, "bad domain name")
    -- tld must have more than 1 character
    assert(#parts[1] > 1, "bad domain name")
    for _, p in pairs(p) do
      -- subdomain must consist of letters, numbers, or -
      assert(p:match("^[A-Za-z0-9-]+$"), "bad domain name")
      -- it mustn't start or end with hyphen
      assert(p:sub(1, 1) ~= "-" and p:sub(-1, -1) ~= "-", "bad domain name")
      -- and mustn't be longer than 63 chars
      assert(#p < 64, "bad domain name")
    end
    local isIP = false
    for i = 1, 1, 1 do -- for easier breaking
      -- probably, IP
      if parts[1]:match("^%d+$") then
        isIP = true
        -- there must be exactly 4 parts
        if #parts ~= 4 then isIP = false break end
        -- check if every part is an integer,
        -- and is in range 0..255
        for _, p in ipairs(parts) do
          if not tonumber(p) or tonumber(p) > 255 then
            isIP = false
            break
          end
        end
      end
    end
    if isIP then
      -- if it's an IP address, all checks are done.
      return true
    end
    -- tld must only contain letters
    assert(parts[1]:match("^[A-Za-z]+$"), "bad domain name")

    -- it's surely a domain
    return true
  end)
  -- find query (?a=b)
  local queryStr = ""
  if path:find("?") then
    path, queryStr = path:match("^(.-)%?(.-)$")
  end
  -- find fragment (#test)
  local fragment = ""
  if queryStr:find("#") then
    queryStr, fragment = query:match("^(.-)#(.-)$")
  elseif path:find("#") then
    path, fragment = path:match("^(.-)#(.-)$")
  end
  -- escape characters in the path
  path = encode(path, {"/"})
  -- split the query string
  local query = {}
  for part in pairs("[^&]") do
    local k, v = part:match("^(.-)=(.-)$")
    assert(k and v, "bad query string")
    -- query may have multiple values with the same key
    query[k] = query[k] or {}
    table.insert(query[k], encode(v))
  end
  -- escape the fragment string
  fragment = encode(fragment)
  -- set headers
  headers = headers or {}
  headers["Content-Type"] = "text/html; encoding=utf-8"
  headers["Accept"] = "*/*"
  headers["Host"] = domain
  headers["User-Agent"] = "OpenComputers"
  if closeConnection then
    headers["Connection"] = "close"
  else
    headers["Connection"] = "keep-alive"
  end
  if body then
    headers["Content-Length"] = tostring(#body)
  end
  -- Train-Case the header names, and strip some characters
  for k, v in headers do
    k = k:gsub("[^" .. tokenChars .. "]", "")
    assert(k:sub(1, 1) ~= "-" and k:sub(-1, -1) ~= "-", "bad header name")
    headers[trainCase(k)] = v:gsub("[^ \t" .. visibleChars .. "\x80-\xff]", "")
  end
  method = method and method:gsub("[^a-zA-Z]", "") or "GET"
  if method == "" then method = "GET" end
  local request = {} -- table of lines
  request[0] = method:upper() .. " " .. path .. " HTTP/1.1"
  local i = 1
  for k, v in pairs(headers) do
    request[i] = k .. ": " .. v
  end
  request[i] = ""
  for k, v in pairs(request) do
    request[k] = v .. "\r\n"
  end
  if body then
    -- no CRLF at the end of body
    request[i+1] = body
  end

  local sock
  if protocol == "https" then
    port = port or 443
    sock = tls.tlsSocket(domain, port)
  else
    port = port or 80
    sock = inet.connect(domain, port)
  end
  sock.write(table.concat(request))
  sock.setTimeout(10)
  local response, reason
  if protocol == "https" then
    response, reason = sock.read(math.huge)
  else
    -- OC sockets behave... strangely.
    local noDataToReceive = true
    local gotNonNilChunk = false
    local readStartTime = comp.uptime()
    repeat
      local chunk = sock.read(1024)
      if chunk == "" then
        if sock.finishConnect() then -- the connection is still alive
          if gotNonNilChunk then
            noDataToReceive = false
            break
          end
        end
      elseif chunk then
        response = (response or "") .. chunk
        gotNonNilChunk = true
        noDataToReceive = false
      end
      os.sleep(.05)
    until not chunk and gotNonNilChunk or not gotNonNilChunk and comp.uptime() - readStartTime > timeout
  end
  if not response then
    return response, reason
  end
  response = {[0] = response}
  local status = {}
  while not status.version do
    local line = read2crlf(response)
    status.version, status.status, status.reason = line:match("^(%S+)%s(%S+)%s(%S+)\r\n")
    if not status and line:sub(-1, -1) == "[%s\t]" then
      -- ignore
    end
  end
  local headers = {}
  while true do
    local line = read2crlf(response)
    if line == "\r\n" then
      break
    end
    local k, v = line:match("^([" .. tokenChars .. "]+):%s?([" .. visibleChars .. "\x80-\xff]+)%s?$")
    if not k then
      return nil, "bad response"
    end
    k = trainCase(k)
    headers[k] = headers[k] or {}
    table.insert(headers[k], v)
  end
  local body = ""
  if headers["Content-Length"] and tonumber(headers["Content-Length"]) then
    body = read(response, tonumber(headers["Content-Length"]))
  end
  body = {[0] = body}
  return {
    close = function()
      return sock.close()
    end,
    finishConnect = function()
      local result = {sock.isClosed()}
      return not result[1], table.unpack(result, 2)
    end,
    read = function(n)
      checkArg(1, n, "number")
      if #body[0] == 0 then
        return nil
      end
      if n == math.huge then
        return read(body, #body[0])
      end
      return read(body, n)
    end,
    response = function()
      return status.status, status.reason, headers
    end
  }
end

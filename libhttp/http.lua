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
  if protocol == "http" then
    if kwargs.body and kwargs.headers then
      return inet.connect(url, kwargs.body, kwargs.headers)
    elseif kwargs.body then
      return inet.request(url, kwargs.body)
    elseif kwargs.headers then
      return inet.request(url, nil, kwargs.body)
    end
  else
    local body, headers, method = kwargs.body, kwargs.headers, kwargs.method
    check(headers, "headers", "table", "nil")
    check(method, "method", "string", "nil")
    check(body, "body", "string", "nil")
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
    end
    -- escape characters in the path
    path = path:gsub("[^A-Za-z0-9-_.~]", function(c)
      return "%" .. ("%02X"):format(c:byte())
    end)
    -- split the query string
    local query = {}
    for part in pairs("[^&]") do
      local k, v = part:match("^(.-)=(.-)$")
      assert(k and v, "bad query string")
      -- query may have multiple values with the same key
      query[k] = query[k] or {}
      table.insert(query[k], v)
    end
    headers = headers or {
      ["Content-Type"] = "text/html; encoding=utf8",
      ["Accept"] = "*/*",
      ["Host"] = domain,
      [""]
    }
    method = method and method:gsub("[^a-zA-Z]", "") or "GET"
    if method == "" then method = "GET" end
    local request = {} -- table of lines
    request[0] = method:upper() .. " " .. path .. " HTTP/1.1"
  end
end

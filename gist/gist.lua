-- Libraries & APIs --
local com = require("component")
local fs = require("filesystem")
local unicode = require("unicode")
local shell = require("shell")
local inetapi = require("internet")
local term = require("term")
local text = require("text")

-- Components --
local inet = com.internet

-- Dyn. Libs --
if not fs.exists("/usr/lib/json.lua") or not loadfile("/usr/lib/json.lua") then
  if not fs.exists("/usr/lib") then
    fs.makeDirectory("/usr/lib")
  end
  local f = io.open("/usr/lib/json.lua", "w")
  for chunk in inetapi.request("http://regex.info/code/JSON.lua") do
    f:write(chunk)
  end
  f:close()
end

local json = loadfile("/usr/lib/json.lua")()

-- Program Variables --
local gResponse = {}
local args, options = shell.parse(...)
local auth = nil

-- Program Constants --
local URLS = {
  basic = "https://api.github.com/gists/{id}",
  post = "https://api.github.com/gists",
  gitio = "https://git.io/create"
}

-- Functions --

local function isin(tbl, value)
  for k, v in pairs(tbl) do
    if v == value then
      return true, k
    end
  end
  return false
end

local function format(args)
  local base = args.base
  args.base = nil
  for k, v in pairs(args) do
    local p1, p2 = base:find("{" .. k .. "}")
    p1 = p1 - 1
    p2 = p2 + 1
    base = unicode.sub(base, 1, p1) .. v .. unicode.sub(base, p2, -1)
  end
  return base
end

local function request(url, headers)
  if gResponse[url] then
    return gResponse[url]
  end
  if headers == true and auth then
    headers = {
      Authorization = "token " .. auth,
      ["User-Agent"] = "Fingercomp's OpenComputers Gist Client https://github.com/OpenPrograms/Fingercomp-Programs/gist/"
    }
  end
  local response = ""
  local req, reason = inet.request(url, nil, headers)
  if req == nil then
    return {}
  end
  for atps = 1, 100, 1 do
    local finish, reason = req.finishConnect()
    if finish == false then
      os.sleep(.1)
    elseif not finish and reason then
      return finish, reason
    else
      break
    end
  end
  if not req.finishConnect() then
    return {}
  end
  while true do
    local chunk = req:read()
    if chunk == nil then break end
    response = response .. chunk
  end
  req:close()
  gResponse[url] = json:decode(response)
  return gResponse[url]
end

local function post(url, data, noDecode, checkGitio, headers)
  if headers == true and auth then
    headers = {
      Authorization = "token " .. auth,
      ["User-Agent"] = "Fingercomp's OpenComputers Gist Client https://github.com/OpenPrograms/Fingercomp-Programs/gist/" -- is that valid?
    }
  end
  local response = ""
  local req, reason = inet.request(url, data, headers)
  if req == nil then
    return not noDecode and {} or nil
  end
  for atps = 1, 150, 1 do
    local finish, reason = req.finishConnect()
    if finish == false then
      os.sleep(.1)
    elseif not finish and reason then
      return finish, reason
    else
      break
    end
  end
  if not req.finishConnect() then
    return not noDecode and {} or nil
  end
  while true do
    local chunk = req:read()
    if chunk == nil then break end
    response = response .. chunk
    if checkGitio and ({req.response()})[3]["Content-Type"][1]:find("text/html") then
      for i = 1, unicode.len(response), 256 do
        local bit = unicode.sub(response, i, i + 255)
        local match = bit:match("^.+https://gist.github.com/%w-/([0-9a-fA-F]+).+$")
        if match then
          return match
        end
      end
    end
  end
  req:close()
  if checkGitio then
    return not noDecode and {} or nil
  end
  if not noDecode then
    return json:decode(response)
  end
  return response
end

local function isIDValid(id)
  local gitio = false
  local url = id
  if not url:match("https?://git.io/%w+") and not url:match("gist.github.com/%w*/?%x+") then
    url = format{base=URLS.basic, id=id}
  else
    gitio = true
  end
  local response = post(url, nil, gitio, gitio, true)
  if not response or (not gitio and not response.url and (not response.message or response.message == "Not Found") or not response and gitio) then
    return false
  elseif gitio and not response then
    return false
  end
  if gitio then
    id = response
  end
  return id, gitio
end

local function getFileList(id)
  local response = request(format{base=URLS.basic, id=id}, true)
  local files = {}
  for k, v in pairs(response.files) do
    table.insert(files, k)
  end
  return files
end

local function getFileInfo(id, filename)
  local response = request(format{base=URLS.basic, id=id}, true)
  return response.files[filename]
end

local function getFullResponse(id)
  return request(format{base=URLS.basic, id=id}, true)
end

local function shorten(url, code)
  local data = "url=" .. url .. (code and "&code=" .. code or "")
  return post(URLS.gitio, data, true)
end

local function help()
  print("USAGE: gist [--t=oauth_token] [-p] [--u=gist] [--P=mode] [--d=desc] [-sRqQlriG] [--f=filename] <id> [file]")
  print("\t\tUPLOAD:")
  print(" -p\tUpload file(s)")
  print(" --P=mode or --public=mode\n\tSet public/secret. Possible options: s (secret), p (public)")
  print(" --d=description or --desc=description\n\tSet gist description")
  print(" --u=gist or --update=gist\n\tUpdates gist (needs correct token to work)")
  print("\tSpecify file(s) as arguments: <path/to/file>=<gistfile>")
  print("\t\tDOWNLOAD/OTHER:")
  print(" --t=oauth_token or --token=oauth_token\n\tUse the provided token. Increases limits for API operations. If uploading, posts the gist into the user's account.")
  print(" -t\tPrompt for a token")
  print(" -s\tShorten the URL via Git.io. Also can be used when uploading files.")
  print(" -R\tShow URL to the raw file contents")
  print(" -q\tQuiet mode")
  print(" -Q\tSuperquiet mode: do not show errors")
  print(" -l\tList files and quit")
  print(" -r\tSave to file even if it exists")
  print(" -i\tShow the file information")
  print(" -G\tShow the gist information")
  print(" --f=filename or --file=filename\n\tSpecify the gist file to work with")
  print(" <id>\tGist ID or Git.io URL")
  print(" [file]\tLocal file to save to")
end

local function smout(text, isError)
  if options.q and not isError then return end
  if options.Q then return end
  if isError then
    io.stderr:write(text .. "\n")
    return
  end
  print(text)
end

-- Main --

if #args < 1 then
  help()
  return
end

do
  local t = options.t or options.token
  if t then
    if t == true then
      local input = term.read({pwchar="*"})
      if input and type(input) == "string" then
        options.t = text.trim(input)
        t = options.t
      end
    end
    if type(t) == "string" and t:len() == 40 and t:match("^" .. ("%x"):rep(40) .. "$") then
      auth = options.t
    else
      smout("Incorrect token!", true)
      return
    end
  end
end

if options.p then
  local public = true
  if options.P then
    if options.P == "s" or options.P == "secret" or options.P == "private" then
      public = false
    end
  end
  local description = options.d or options.desc or ""
  local files = {}
  for _, f in pairs(args) do
    local path, filename = f:match("(.+)=(.+)")
    if path == nil or filename == nil then
      smout("Unrecognized argument: " .. f, true)
      smout("Expected: <path/to/file>=<gistfile>")
      smout("Ex.: /test/helloworld.lua=helloworld.lua")
      return
    end
    if not fs.exists(path) then
      smout("No such file: " .. path, true)
      return
    end
    if fs.isDirectory(path) then
      smout("Not a file: " .. path, true)
      return
    end
    if filename:match("gistfile%d+") then
      smout("This file format Gist uses internally, please choose another name: " .. filename, true)
      return
    end
    local rq_file = io.open(path, "r")
    local data = rq_file:read("*a")
    rq_file:close()
    files[filename] = {content=data}
  end
  local post_tbl = {
    description = description,
    public = public,
    files = files
  }
  local posturl = URLS.post
  if (options.u or options.update) and type(options.u) == "string" and auth then
    local ID, shouldRecheck = isIDValid(options.u or options.update)
    if not ID or (ID and shouldRecheck and not isIDValid(ID)) then
      smout("This gist ID is not valid!", true)
      return
    end
    posturl = posturl .. "/" .. ID
  elseif options.u or options.update then
    smout("Expected --u=GISTID and --token=OAUTHTOKEN", true)
    return
  end
  local response = post(posturl, json:encode(post_tbl), nil, nil, true)
  if response.html_url then
    if not options.s then
      print((public and "Public " or "Secret ") .. "gist " .. (posturl == URLS.post and "create" or "update") .. "d! " .. response.html_url)
    else
      local code = type(options.s) == "string" and options.s
      local short, reason = shorten(response.html_url, code)
      if not short or short == "" then
        reason = reason or "unknown"
        smout("Could not shorten url: " .. reason, true)
        print("Gist URL: " .. response.html_url)
      else
        print((public and "Public " or "Secret ") .. "gist " .. (posturl == URLS.post and "create" or "update") .. "d! https://git.io/" .. short)
      end
    end
  else
    smout("Unexpected error", true)
  end
  return
end

if options.s then
  local code
  if type(options.s) == "string" then
    code = options.s
  end
  local short, reason = shorten(args[1], code)
  if not short or short == "" then
    reason = reason or "unknown"
    smout("Could not shorten URL: " .. reason, true)
  else
    print("Short URL: https://git.io/" .. short)
  end
  return
end

local ID, shouldRecheck = isIDValid(args[1])
if not ID or (ID and shouldRecheck and not isIDValid(ID)) then
  smout("This gist ID is not valid!", true)
  return
end

if options.G then
  local fr = getFullResponse(ID)
  print((fr.public and "Public " or "Secret ") .. "gist " .. fr.id)
  print(" " .. fr.description)
  print(" Owner: " .. fr.owner.login)
  print(" Comments: " .. fr.comments)
  print(" Forks: " .. #fr.forks)
  print(" Revisions: " .. #fr.history)
  return
end

local files = getFileList(ID)

if options.l then
  print("Files:")
  for _, f in pairs(file) do
    print(" * " .. f)
  end
  return
end

if #files > 1 and not options.f and not options.file then
  smout("Please specify a file:", true)
  for _, f in pairs(files) do
    smout(" * " .. f)
  end
  return
end

local req_file = options.f or options.file or files[1]

if not isin(files, req_file) then
  smout("No such file!", true)
  return
end

local file_info = getFileInfo(ID, req_file)

if options.R then
  print(file_info.raw_url)
  return
end

if options.i then
  print("Language: " .. (file_info.language or "none"))
  print("Size: " .. file_info.size)
  print("Type: " .. file_info.type)
  return
end

if args[2] then
  if fs.exists(args[2]) and not options.r then
    smout("File already exists!", true)
    return
  end
  local f = io.open(args[2], "w")
  f:write(file_info.content)
  f:close()
  smout("Successfully saved to file: \"" .. args[2] .. "\"!")
else
  print(file_info.content)
end

-- vim: autoindent expandtab tabstop=2 shiftwidth=2 :

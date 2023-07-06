local com = require("component")

local tls = require("tls13")
local tlsBase64 = require("tls13.base64")
local tlsErrors = require("tls13.error")

local data = com.data
local inet = com.internet

local cerLines = {}

for line in io.lines("/home/client.cer") do
  table.insert(cerLines, line)
end

local cer =
  assert(tlsBase64.decode(table.concat(cerLines, "", 2, #cerLines - 1)))

f = assert(io.open("/home/priv.der", "rb"))
local priv = f:read("a")
f:close()

local privKey = com.data.deserializeKey(priv, "ec-private")

local addr, path = ...
addr = addr or "localhost:12345"
path = path or "/"

local sock = assert(inet.connect(addr))

for i = 1, 100 do
  local success, err = sock.finishConnect()

  if success then
    break
  elseif success == nil then
    error(err)
  end

  os.sleep(0.05)
end

if not sock.finishConnect() then
  error("timeout")
end

local function assertOk(result, err)
  if result == nil then
    local traceback = err and err.traceback or debug.traceback()
    io.stderr:write(("%s:\n%s"):format(err, traceback))
    os.exit(1)
  else
    return result
  end
end

local serverName = addr:match("^(.+):%d+$")

io.stderr:write("connected\n")

sock = assertOk(tls.wrap(sock, nil, {
  keyLogFile = io.open("./keyLog.txt", "a"),
  alpnProtocol = "http/1.1",
  serverName = serverName,

  onCertificateRequest = function(signatureAlgorithms, certificateRequest)
    local sigalg = tls.profiles.opencomputers.signatureAlgorithms()[1]

    return {
      encodedCert = cer,
      algorithm = sigalg,
      privateKey = privKey,
    }
  end,
}))

io.stderr:write("handshake finished\n")
local ctx = sock:inner():establishedContext()
io.stderr:write(("- HelloRetryRequest received: %q\n"):format(ctx.helloRetried))
io.stderr:write(
  ("- CertificateRequest received: %q\n"):format(ctx.clientCertificateRequested)
)
io.stderr:write(
  ("- client certificate sent: %q\n"):format(ctx.clientCertificateSent)
)
io.stderr:write(("- cipher suite: %s\n"):format(ctx.cipherSuite.name))
io.stderr:write(("- named group: %s\n"):format(ctx.namedGroup.name))
io.stderr:write(
  ("- server signature algorithm: %s\n")
    :format(ctx.serverSignatureAlgorithm.name)
)

if ctx.clientCertificateSent then
  io.stderr:write(
    ("client signature algorithm: %s\n")
      :format(ctx.clientSignatureAlgorithm.name)
  )
end

io.stderr:write(("- ALPN protocol: %s\n"):format(ctx.alpnProtocol))

local req = [[
GET %s HTTP/1.1
Host: %s
Connection: close

]]
req = req:format(path, addr):gsub("\n", "\r\n")

io.stderr:write(("sock:write -> %s\n"):format(assertOk(sock:write(req))))

while true do
  local chunk, err = sock:read()

  if chunk == nil and not err then
    break
  elseif chunk == nil and err == tlsErrors.tls.remoteCloseAlert then
    io.stderr:write(("sock:read -> %s\n"):format(err))

    break
  end

  print(assertOk(chunk, err))
end

sock:close()

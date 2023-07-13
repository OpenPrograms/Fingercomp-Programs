-- An example that showcases the TLS 1.3 library.

local com = require("component")

local tls = require("tls13")
local tlsBase64 = require("tls13.base64")
local tlsErrors = require("tls13.error")

local data = com.data
local inet = com.internet

local cerLines = {}

for line in io.lines("/usr/share/doc/tls13/example/client.cer") do
  table.insert(cerLines, line)
end

local cer =
  assert(tlsBase64.decode(table.concat(cerLines, "", 2, #cerLines - 1)))

f = assert(io.open("/usr/share/doc/tls13/example/priv.der", "rb"))
local priv = f:read("a")
f:close()

local privKey

if com.data.deserializeKey then
  -- this needs a T3 data card
  privKey = com.data.deserializeKey(priv, "ec-private")
end

--------------------------------------------------------------------------------

local addr, path = ...
addr = addr or "localhost:12345"
path = path or "/"

-- connect to the remote host
-- make sure to use the COMPONENT's method here! (see local inet def above)
local sock = assert(inet.connect(addr))

-- this is a very crude way of waiting until we've connected
-- your program should do something more sane about that
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

-- a helper function to handle libtls13's errors
local function assertOk(result, err)
  if result == nil then
    -- errors coming from libtls13 have an associated traceback
    local traceback = err and err.traceback or debug.traceback()
    io.stderr:write(("%s:\n%s\n"):format(err, traceback))

    -- some errors may also have a cause associated with them...
    local cause = err and err.cause

    while cause do
      -- ...which may have their own traceback!
      local traceback = cause.traceback

      if traceback then
        io.stderr:write(("CAUSED BY: %s:\n%s\n"):format(cause, traceback))
      else
        io.stderr:write(("CAUSED BY: %s\n"):format(cause))
      end

      -- as well as their own cause
      cause = cause.cause
    end

    os.exit(1)
  else
    return result
  end
end

-- used for ALPN: it needs a hostname (technically IP addresses are not allowed,
-- but we kinda don't care about that...)
local serverName = addr:match("^(.+):%d+$")

-- at this point the connection is ready for TLS handshaking!
io.stderr:write("connected\n")

--------------------------------------------------------------------------------

-- this wraps a socket and performs a full TLS 1.3 handshake.
-- (assertOk aborts the program on error.)
sock = assertOk(tls.wrap(sock, nil, {
  -- a key log file can be loaded in Wireshark to inspect encrypted traffic.
  -- obviously, optional. you probably even want to NOT specify this option
  -- here.
  keyLogFile = io.open("./keyLog.txt", "a"),

  -- the ALPN protocol is provided here. also optional, though it's
  -- a good idea to include it whenever possible.
  -- if you're planning to implement h2 (bless you), you'll HAVE TO negotiate
  -- the protocol here. and you'll probably also want an http/1.1 fallback as
  -- well -- see `alpnProtocols` explained in a doc comment in tls13/init.lua.
  alpnProtocol = "http/1.1",

  -- a lot of web servers require you to tell them what domain name you used to
  -- discover them (so that they can host many websites on a single machine AND
  -- have each have its own certificate).
  -- so, though it's optional, you'll probably want to provide it here
  -- if you can.
  -- note, though, that it's sent out in plaintext (not encrypted). not that you
  -- care, I guess, it's OC after all.
  serverName = serverName,

  -- this callback is called if the server wants you to present your client
  -- certificate. if you don't have any, just don't specify the callback.
  -- alternatively, you may return `false` (it HAS to be `false`, not `nil`.
  -- `nil` is treated as an error, and the second return values as the error
  -- message/object).
  --
  -- for testing purposes, this example includes a client certificate and its
  -- private key. it'll expire quickly (by the time you're reading, it's
  -- probably already dead). generate your own if you happen to need this, but
  -- most likely you just won't.
  onCertificateRequest = function(signatureAlgorithms, certificateRequest)
    if privKey then
      local sigalg = tls.profiles.opencomputers.signatureAlgorithms()[1]

      return {
        encodedCert = cer,
        algorithm = sigalg,
        privateKey = privKey,
      }
    else
      return false
    end
  end,
}))

-- at this point the TLS 1.3 handshake is finished successfully.
io.stderr:write("handshake finished\n")

-- this gets you a copy of the establishedContext. you can use it to see what
-- ALPN protocol you've ended up with, or just print out a bunch of info as I do
-- here.
local ctx = sock:inner():establishedContext()

-- true/false.
io.stderr:write(("- HelloRetryRequest received: %q\n"):format(ctx.helloRetried))

-- true/false.
io.stderr:write(
  ("- CertificateRequest received: %q\n"):format(ctx.clientCertificateRequested)
)

-- true/false.
io.stderr:write(
  ("- client certificate sent: %q\n"):format(ctx.clientCertificateSent)
)

io.stderr:write(("- cipher suite: %s\n"):format(ctx.cipherSuite.name))
io.stderr:write(("- named group: %s\n"):format(ctx.namedGroup.name))
io.stderr:write(
  ("- server signature algorithm: %s\n")
    :format(ctx.serverSignatureAlgorithm.name)
)

-- the condition is true/false. if false, clientSignatureAlgorithm will be nil.
if ctx.clientCertificateSent then
  io.stderr:write(
    ("- client signature algorithm: %s\n")
      :format(ctx.clientSignatureAlgorithm.name)
  )
end

-- the negotiated application-layer protocol. here it's most likely to be
-- http/1.1.
io.stderr:write(("- ALPN protocol: %s\n"):format(ctx.alpnProtocol))

--------------------------------------------------------------------------------

-- send out a primitive HTTP/1.1 GET request.
local req = [[
GET %s HTTP/1.1
Host: %s
Connection: close

]]
req = req
  :format(path:gsub(
    "[^a-zA-Z0-9/]",
    -- brute percent-encoding. I had experience parsing URLs in C -- it's not
    -- that simple, I tell you. so this program accepts a plain path.
    --
    -- I don't remember what precise set of symbols I need to encode this way,
    -- so I'm just doing this for all non-alphanumeric bytes save /.
    function(c) return ("%%%02x"):format(c:byte()) end
  ), addr)
  -- lines are terminated with \r\n in HTTP. I don't like that.
  :gsub("\n", "\r\n")

-- if everything goes well, you'll see #req here.
io.stderr:write(("sock:write -> %s\n"):format(assertOk(sock:write(req))))

while true do
  -- this blocks. as explained in README.md (/usr/share/doc/tls13/README.md),
  -- you can wrap the sock above (before you pass it to libtls) to call
  -- `coroutine.yield` on I/O operations and then figure it out from there.
  -- note you'll want to use tls.wrapRaw for the handshake then.
  --
  -- ...alternatively, use OpenOS threads. it's all coroutines either way.
  local chunk, err = sock:read()

  -- a bit of a hack: errors originating outside of libtls13 are passed as-is.
  -- this includes OC socket errors. on EOF, the internet card's socket's read
  -- method returns a plain `nil` without a message. so libtls13 will give you a
  -- `nil` for an `err`. this is how you can detect an abrupt close.
  --
  -- (TLS requires each party to notify its peer before closing the connection
  -- so that the EOF is protected by TLS as well. if your server is
  -- well-behaved, you'll get into the elseif branch down there.)
  if chunk == nil and not err then
    break
  elseif chunk == nil and err == tlsErrors.tls.remoteCloseAlert then
    -- libtls13's error objects can be compared by code (see the line above).
    -- makes for nicer error handling.

    -- remote alert errors always have an associated cause with the precise type
    -- of the error (one from tlsErrors.alert).
    -- but the error message includes the description of the alert for
    -- convenience.
    -- btw, libtls13's error objects have a __tostring metamethod but are
    -- otherwise tables. if you need a string, call `tostring` explicitly.
    io.stderr:write(("sock:read -> %s\n"):format(err))

    -- this breaks out of the loop to close the connection.
    -- normally, you may want to send out the remaining data to the server and
    -- only then close the connection (sending out an alert as well),
    -- since the closure alert only indicates the remote peer closed its side of
    -- the connection. you can still send data to it. presumably.
    -- if you know C and Berkley sockets, it's kind of like `shutdown(SHUT_WR)`
    -- on their side.
    -- in reality most servers just `close()` the socket, which is a bit
    -- unfortunate. though probably they just sticked to the old, TLS 1.2-
    -- behavior, which required just that. oh well.
    --
    -- either way, OC has no notion of shutting down a socket. this, too, is
    -- unfortunate.
    break
  end

  -- if libtls13 does not experience an internal error, err is either whatever
  -- was produced outside the library, or an error defined in tlsErrors.tls.
  --
  -- remoteCloseAlert was handled above. you do want handle that one separately.
  -- probably localCloseAlert as well. remoteAlert/localAlert are both fatal and
  -- you should treat them as such.
  print(assertOk(chunk, err))
end

-- we broke out of the loop above, so we just close the connection.
sock:close()

# libtls
*Transferring the data over a secure, TLS connection!*

Available for downloading on the [Hel Repository](https://hel.fomalhaut.me/#packages/libtls).

## What TLS is, briefly.
This is an additional, intermediate layer between the application data layer and transport control layer, that maintains the security and eavesdropping prevention.

```
     Application Data
            ⇅
 Transport Layer Security
            ⇅
Transport Control Protocol
```

Before sending application data, the client must first negotiate a procedure known as handshake. During handshake, the server and client choose a cipher suite to use, the client validates chain of certificates that's sent by the server, they exchange the keys that will be used to encrypt the data and confirm that each side of the connection has properly generated the keys.

A comparably slow symmetric cryptography (generally, ECDSA, or RSA, which is what this library uses) is only used to exchange the keys that'll be used for rather quick symmetric ciphers (e.g., AES-128, or AES-256). There are two cipher keys, two MAC keys, and two initialization vectors for block ciphers if they are used. The keys are different for the client and the server to prevent situations when the packet is sent back to its sender by someone else.

To prevent traffic modification (picking a packet at some time and sending it again to the recipient later), each encrypted message includes a MAC (Message Authentication Code), which is basically a hash of the message and a sequence number. The sequence number is kept seperately for read and write operations. It starts counting from 0 and increments by 1 each time the packet is sent (or recieved). The max amount of packets that can be sent over a specific connection is 2⁶⁴ (18446744073709551616). As each packet can contains up to 16 kB of payload, you can send no more than 16777216 TB. This is more than enough.

The benefit of TLS is that already-existing applications do not require a lot of effort to switch to the secure connection, as the data stream is kept unmodified on the application layer. The server only needs to generate the private key, get a certificate, and use TLS-wrapped sockets.

## What this library is, seriously.
This is an implementation of TLSv1.2. It wraps the internet card's basic sockets, and tries to mimic the behaviour of internet card's sockets, at least, on a high level. It encrypts, sends, recieves, decrypts, validates, and returns the data stream as a binary string.

**It doesn't validate the certificates!** Yeah, it's kind of pointless from the security's point of view, as anyone can send a fake certificate, and thus easily decrypt your data, but, at least, the library makes it possible to connect to services using TLS.

### Why does it not validate the certificates?
First, it takes too much effort to *actually understand* what's written in the X.509 certificate standard. Barely an excuse, I know.

Second, it requires to store the root certificates that we should trust.

Third, I'm too lazy to bother enough to actually do something about certificate validation.

So, eh. Maybe. One day. Somewhen in this century. I hope.

## Usage
Those who understand a code quicker than a text, here's a snippet:

```lua
local tls = require("tls")

local sock = tls.tlsSocket("github.com", 443)
sock.write([[GET / HTTP/1.1\r
Host: github.com\r
Connection: close\r
User-Agent: OpenComputers\r
\r
]])

local data, reason = sock.read()
if not data then
  print(reason)
end

print(#data)
```

Below, I'll describe what is going on there in details.

First, you need to connect to server. You can either wrap an existing socket or create a new one.

* `tls.tlsSocket(url: string[, port: number[, extensions: table]])` — create a new TLS-wrapped socket with optional TLS extensions.
* `tls.tlsSocket(urlWithPort: string[, extensions: table])` — the same as above, but the port is included in the url.
* `tls.wrap(sock: userdata[, extensions: table])` — wrap an existing socket.

Either way, you get a table of functions.

* `socket.write(data: string)` — writes data to the socket stream.
* `socket.read([records: number]): string` — reads data from the socket stream.
* `socket.close()` — properly closes the socket.
* `socket.id(): string` — returns the socket's ID.
* `socket.isClosed(): boolean` — checks whether the socket is open.
* `socket.finishConnect(): boolean[, string]` — directly calls raw socket's method with the same name.
* `socket.setTimeout(n: number)` — sets the read timeout, in seconds.

### Extensions

The `extensions` argument is a table of extensions that looks like this:

```lua
{
  ["\x00\x10"] = "\x09\x08http/1.1"
}
```

The key is an extension type, and the extension data is the value. The length of value is calculated automatically.

## Hardware dependencies
* Advanced cipher block (Computronics). It provides RSA encryption.
* Second-tier data card. It has sha256 and md5 HMAC algorithms, and secure random generator.
* Internet card. I guess I don't need to explain why this is needed.

## Some random questions

### WHY IS THIS THING SO SLOOOOOOOOW?
Because OpenComputers. It only takes 5 seconds to connect. While I was debugging the library, it took **several minutes** to do so! 15 times faster, that is.

Seriously, though, there's a lot of time-consuming operations that need to be done to create a TLS connection. Perhaps the only way to make it faster is adding support for TLS sockets to OpenComputers.

### What's that "unknown signature algorithm" // "unknown extension" thingy?
This is something that I'd be glad to fix, basically. Please create an issue at the tracker, including the sequence of period-separated numbers in exact order.

## License
This program uses the Apache 2.0 license. The text of the license can be obtained [here](http://www.apache.org/licenses/LICENSE-2.0).

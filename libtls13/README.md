# libtls13

A TLS 1.3 client implementation for OpenComputers.

Additionally:

- DER decoder

- X.509 certificate parser

- Cryptographic library (pure Lua implementations):

  - RSA signature verification

  - AES ciphers (+ GCM)

  - SHA2 family of hash functions

  - Curve25519: X25519 and Ed25519 (port of libsodium / ref10)

  - ECDSA (secp384r1) signature verification

Requires a T2 data card for RNG.

Needs Lua 5.3+. Lua 5.2 is unsupported and won't work.

TLS support:

- Can perform a certificate-only handshake (PSKs aren't supported).

- Tolerates hello retry requests.

- Supports client certificates (no idea why you'd need that, but it's there).

- ALPN and server\_name extensions.

- Only does TLS 1.3. If you need TLS 1.2, see `libtls` in this repository.
  And if you need TLS 1.1-, you don't.

Crypto:

- Cipher suites:

  - `TLS_AES_128_GCM_SHA256`
  - `TLS_AES_256_GCM_SHA384`

- Signature algorithms:

  - `rsa_pss_rsae_sha256`, `rsa_pss_rsae_sha384`, `rsa_pss_rsae_sha512`
  - `rsa_pss_pss_sha256`, `rsa_pss_pss_sha384`, `rsa_pss_pss_sha512`
  - `ecdsa_secp256r1_sha256` (needs a T3 data card), `ecdsa_secp384r1_sha384`
  - `ed25519`

- Key exchange (groups):

  - `secp256r1`, `secp384r1` (both need a T3 data card)
  - `x25519`

Assumes blocking I/O for simplicity.
Since it's Lua, use coroutines if you don't like that.
(Wrap a dummy "socket" that yields when reading/writing data.)

## Examples
See `example/client.lua`.

## Documentation
Everything that matters has a doc comment in the code.
The main module (`src/init.lua`) in particular.

The example program is also heavily documented.

## Tests
There are a few tests for the crypto stuff.
You'll need `busted` to run them.
Don't forget to fetch the submodules: I'm using test vectors from Google's
Project Wycheproof and a JSON library to parse test data.

## Security
It does consistency checks mandated by the RFC.
But then it also blindly believes whatever's written in certificates.
MITM is thus trivial.

(I did think about implementing cert validation this time, hence the gigantic
X.509 parser, but when I read about DN matching, I decided it wasn't worth my
time.
You may want to try your hand at it if you ever wished to make your own icu in
Lua.)

RSA is notorious for being hard to get right.
I didn't even try.

## Performance
Fast enough.
With RSA certificates handshakes are about 0.25 s longer.
If you're in control of your server, try using certs with EC public keys.

## Future work
Not that I'm planning to do it.
But if you have a free summer or two, here's what would be nice:

- Certification path validation. Pretty tough.
- PSK support and 0-RTT data. A bit tricky.
- Integrate TLS 1.2. Roughly two weeks of work, immense benefits.

## Why
You could use this to connect to newer servers that want ephemeral DH.

I just wanted to check out what's new in 1.3, implement finite field / modular
arithmetic in Lua, and write a bunch of parsers.
Also finally learned the order of precedence of bitwise operators.

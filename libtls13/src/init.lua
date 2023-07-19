-- TLS 1.3 client implementation.

local lib = {}

local aes = require("tls13.crypto.cipher.aes")
local gcm = require("tls13.crypto.cipher.mode.gcm")
local group = require("tls13.group")
local handshake = require("tls13.handshake")
local hmac = require("tls13.crypto.hmac")
local oid = require("tls13.asn.oid")
local record = require("tls13.record")
local rsa = require("tls13.crypto.rsa")
local sha2 = require("tls13.crypto.hash.sha2")
local sigalg = require("tls13.sigalg")
local tlsIo = require("tls13.io")
local util = require("tls13.util")

-- Profiles provide algorithms used for establishing cryptographic context.
--
-- A profile consists of 5 functions:
--
-- - cipherSuites: returns a sequence of cipher suites
--
-- - signatureAlgorithms: returns a sequence of algorithms used for signing and
--   verifying handshake signatures
--
-- - certSignatureAlgorithms: returns a sequence of algorithms used for
--   certificate validation (currently unused except to guide server certificate
--   selection)
--
-- - namedGroups: returns a sequence of named groups and key exchange algorithms
--   that operate in those groups to derive shared secrets (such as ECDHE)
--
-- - rng: returns a secure random number generator that creates byte strings of
--   specified length indistinguishable from uniformly random
lib.profiles = {}

function lib.makeCipherSuite(args)
  local code = args.code
  local name = args.name
  local hash = args.hash
  local hmac = args.hmac or hmac.hmac(hash)
  local aead = args.aead

  return {
    code = code,
    name = name,
    hash = hash,
    hmac = hmac,
    aead = aead,
  }
end

function lib.makeSignatureAlgorithm(args)
  local code = args.code
  local name = args.name
  local decodePublicKey = args.decodePublicKey
  local verify = args.verify
  local sign = args.sign

  return {
    code = code,
    name = name,
    decodePublicKey = decodePublicKey,
    verify = verify,
    sign = sign,
  }
end

function lib.makeNamedGroup(args)
  local code = args.code
  local name = args.name
  local generateEagerly = args.generateEagerly
  local decodePublicKey = args.decodePublicKey
  local encodePublicKey = args.encodePublicKey
  local generateKeyPair = args.generateKeyPair
  local deriveSharedSecret = args.deriveSharedSecret

  return {
    code = code,
    name = name,
    generateEagerly = generateEagerly,
    decodePublicKey = decodePublicKey,
    encodePublicKey = encodePublicKey,
    generateKeyPair = generateKeyPair,
    deriveSharedSecret = deriveSharedSecret,
  }
end

lib.profiles.default = {}

function lib.profiles.default.cipherSuites()
  return {
    lib.makeCipherSuite {
      code = 0x1301,
      name = "TLS_AES_128_GCM_SHA256",
      hash = sha2.sha256,
      aead = gcm.gcm(aes.aes128, true),
    },

    lib.makeCipherSuite {
      code = 0x1302,
      name = "TLS_AES_256_GCM_SHA384",
      hash = sha2.sha384,
      aead = gcm.gcm(aes.aes256, true),
    },
  }
end

local rsaPssRsaeSha256 = sigalg.makeRsaPssRsaeSigAlg(sha2.sha256)
local rsaPssRsaeSha384 = sigalg.makeRsaPssRsaeSigAlg(sha2.sha384)
local rsaPssRsaeSha512 = sigalg.makeRsaPssRsaeSigAlg(sha2.sha512)

local rsaPssPssSha256 =
  sigalg.makeRsaPssPssSigAlg(sha2.sha256, oid.hashalgs.sha256)
local rsaPssPssSha384 =
  sigalg.makeRsaPssPssSigAlg(sha2.sha384, oid.hashalgs.sha384)
local rsaPssPssSha512 =
  sigalg.makeRsaPssPssSigAlg(sha2.sha512, oid.hashalgs.sha512)

local ecdsaSecp384r1Sha384 = sigalg.makeEcdsaSecp384r1SigAlg()
local ed25519 = sigalg.makeEd25519SigAlg()

function lib.profiles.default.signatureAlgorithms()
  return {
    lib.makeSignatureAlgorithm {
      code = 0x0807,
      name = "ed25519",
      decodePublicKey = ed25519.decodePublicKey,
      verify = ed25519.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0503,
      name = "ecdsa_secp384r1_sha384",
      decodePublicKey = ecdsaSecp384r1Sha384.decodePublicKey,
      verify = ecdsaSecp384r1Sha384.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0804,
      name = "rsa_pss_rsae_sha256",
      decodePublicKey = rsaPssRsaeSha256.decodePublicKey,
      verify = rsaPssRsaeSha256.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0805,
      name = "rsa_pss_rsae_sha384",
      decodePublicKey = rsaPssRsaeSha384.decodePublicKey,
      verify = rsaPssRsaeSha384.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0806,
      name = "rsa_pss_rsae_sha512",
      decodePublicKey = rsaPssRsaeSha512.decodePublicKey,
      verify = rsaPssRsaeSha512.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0809,
      name = "rsa_pss_pss_sha256",
      decodePublicKey = rsaPssPssSha256.decodePublicKey,
      verify = rsaPssPssSha256.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x080a,
      name = "rsa_pss_pss_sha384",
      decodePublicKey = rsaPssPssSha384.decodePublicKey,
      verify = rsaPssPssSha384.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x080b,
      name = "rsa_pss_pss_sha512",
      decodePublicKey = rsaPssPssSha512.decodePublicKey,
      verify = rsaPssPssSha512.verify,
    },
  }
end

function lib.profiles.default.certSignatureAlgorithms()
  local rsaPkcs1Sha256 = sigalg.makeRsaPkcs1SigAlg(sha2.sha256)
  local rsaPkcs1Sha384 = sigalg.makeRsaPkcs1SigAlg(sha2.sha384)
  local rsaPkcs1Sha512 = sigalg.makeRsaPkcs1SigAlg(sha2.sha512)

  return util.append(lib.profiles.default.signatureAlgorithms(), {
    lib.makeSignatureAlgorithm {
      code = 0x0401,
      name = "rsa_pkcs1_sha256",
      decodePublicKey = rsaPkcs1Sha256.decodePublicKey,
      verify = rsaPkcs1Sha256.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0501,
      name = "rsa_pkcs1_sha384",
      decodePublicKey = rsaPkcs1Sha384.decodePublicKey,
      verify = rsaPkcs1Sha384.verify,
    },

    lib.makeSignatureAlgorithm {
      code = 0x0601,
      name = "rsa_pkcs1_sha512",
      decodePublicKey = rsaPkcs1Sha512.decodePublicKey,
      verify = rsaPkcs1Sha512.verify,
    },
  })
end

function lib.profiles.default.namedGroups()
  return {}
end

-- Extends the default profile with data card algorithms (such as ECDSA).
lib.profiles.opencomputers = util.copyMap(lib.profiles.default)

local function makeOcSignatureAlgorithms()
  if require("tls13.oc").getDataCardOrNil(3) then
    local sigalg = require("tls13.oc.sigalg")
    local ecdsaSecp256r1Sha256 = sigalg.makeEcdsaSecp256r1SigAlg()

    return {
      lib.makeSignatureAlgorithm {
        code = 0x0403,
        name = "ecdsa_secp256r1_sha256",
        decodePublicKey = ecdsaSecp256r1Sha256.decodePublicKey,
        verify = ecdsaSecp256r1Sha256.verify,
        sign = ecdsaSecp256r1Sha256.sign,
      },
    }
  end

  return {}
end

function lib.profiles.opencomputers.signatureAlgorithms()
  return util.append(
    makeOcSignatureAlgorithms(),
    lib.profiles.default.signatureAlgorithms()
  )
end

function lib.profiles.opencomputers.certSignatureAlgorithms()
  return util.append(
    makeOcSignatureAlgorithms(),
    lib.profiles.default.certSignatureAlgorithms()
  )
end

function lib.profiles.opencomputers.namedGroups()
  local rng = lib.profiles.opencomputers.rng()
  local x25519 = group.makeX25519(rng)

  local entries = {
    lib.makeNamedGroup {
      code = 0x001d,
      name = "x25519",
      generateEagerly = true,
      decodePublicKey = x25519.decodePublicKey,
      encodePublicKey = x25519.encodePublicKey,
      generateKeyPair = x25519.generateKeyPair,
      deriveSharedSecret = x25519.deriveSharedSecret,
    },
  }

  if require("tls13.oc").getDataCardOrNil(3) then
    local ocGroup = require("tls13.oc.group")
    local secp256r1 = ocGroup.makeEcdhe(256)
    local secp384r1 = ocGroup.makeEcdhe(384)

    entries = util.append(entries, {
      lib.makeNamedGroup {
        code = 0x0017,
        name = "secp256r1",
        generateEagerly = false,
        decodePublicKey = secp256r1.decodePublicKey,
        encodePublicKey = secp256r1.encodePublicKey,
        generateKeyPair = secp256r1.generateKeyPair,
        deriveSharedSecret = secp256r1.deriveSharedSecret,
      },

      lib.makeNamedGroup {
        code = 0x0018,
        name = "secp384r1",
        decodePublicKey = secp384r1.decodePublicKey,
        encodePublicKey = secp384r1.encodePublicKey,
        generateKeyPair = secp384r1.generateKeyPair,
        deriveSharedSecret = secp384r1.deriveSharedSecret,
      },
    })
  end

  return util.append(entries, lib.profiles.default.namedGroups())
end

function lib.profiles.opencomputers.rng()
  local rng = require("tls13.oc.rng")

  return rng.rng
end

-- Wraps a raw blocking socket and performs a TLS 1.3 handshake.
--
-- - f: the socket object (with read, write, close methods)
--
-- - profile: the selected cryptographic profile
--
-- - options: a table of additional options:
--
--   - alpnProtocol (or alpnProtocols if multiple):
--     a name of an application-layer protocol to negotiate
--     via the ALPN extension
--
--   - serverName (or serverNames if multiple):
--     a hostname of the server (commonly used for HTTPS connections)
--
--   - keyLogFile: a buffered stream to write TLS secrets to
--     (can be loaded in Wireshark to inspect encrypted traffic)
--
--   - onNewSessionTicket: a function called when the server creates a session
--     ticket
--
--     they are useless for this implementation because it does not support
--     PSK handshakes, but can be exported to resume the session
--
--   - onCertificateRequest: a function called when the server requests client
--     authentication via an X.509 certificate
--
--     the callback should return either false if it does not intend to send a
--     certificate, or a table with the following entries:
--
--     - encodedCert: an X.509-encoded certificate
--     - algorithm: a signature algorithm (see makeSignatureAlgorithm)
--     - privateKey: a private key to use for signing
--
-- If the handshake succeeds, returns a buffered IO object (see tls.io)
-- for reading and writing.
-- The underlying handshake session is available via :inner().
--
-- On failure returns nil and either a string message if the error originated
-- outside of this library, or an error object (see tls.error).
function lib.wrapRaw(f, profile, options)
  local buf = tlsIo.wrap(f)
  local recordLayer = record.makeRecordLayer(buf)

  local alpnProtocols

  if options.alpnProtocol and options.alpnProtocol ~= "" then
    alpnProtocols = {options.alpnProtocol}
  elseif options.alpnProtocols then
    alpnProtocols = options.alpnProtocols
  end

  local serverNames

  if options.serverName then
    serverNames = {{hostname = options.serverName}}
  elseif options.serverNames then
    serverNames = {}

    for _, name in ipairs(options.serverNames) do
      if type(name) == "string" then
        name = {hostname = name}
      end

      table.insert(serverNames)
    end
  end

  local hs = handshake.makeSession {
    recordLayer = recordLayer,
    cipherSuites = profile.cipherSuites(),
    signatureAlgorithms = profile.signatureAlgorithms(),
    certSignatureAlgorithms = profile.certSignatureAlgorithms(),
    namedGroups = profile.namedGroups(),
    rng = profile.rng(),
    keyLogFile = options.keyLogFile,
    alpnProtocols = alpnProtocols,
    serverNames = serverNames,

    callbacks = {
      onNewSessionTicket =
        options.onNewSessionTicket or function(newSessionTicket) end,

      onCertificateRequest =
        options.onCertificateRequest
        or function(signatureAlgorithms, certificateRequest) return false end,
    },
  }

  local status, err = hs:handshake()

  if not status then
    return nil, err
  end

  return tlsIo.wrap(hs)
end

-- Wraps an OpenComputers internet card socket and starts a TLS 1.3 handshake.
--
-- It's assumed the socket was created via the component API (using the internet
-- library will not work).
--
-- See wrapRaw for additional information.
function lib.wrap(sock, profile, options)
  profile = profile or lib.profiles.opencomputers

  return lib.wrapRaw(require("tls13.oc.io").wrap(sock), profile, options)
end

return lib

local util = require("tls13.util")

local testUtil = require("test.test-util")(_ENV)

context("X25519 tests #crypto #curve25519", function()
  local curve25519 = require("tls13.crypto.curve25519")

  test("Field-to/from-bytes conversion", function()
    local bytes = ("x"):rep(32):gsub("().", string.char)
    local fe = curve25519.fieldFromBytes(bytes)

    assert.are.equal(
      util.toHex(bytes),
      util.toHex(curve25519.fieldToBytes(fe))
    )
  end)

  context("RFC 7748 test vectors", function()
    test("X25519, test vector 1", function()
      local scalar = util.fromHex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
      )
      local u = util.fromHex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
      )
      local expected =
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
      local actual = util.toHex(curve25519.x25519(scalar, u))

      assert.are.equal(expected, actual)
    end)

    test("X25519, test vector 2", function()
      local scalar = util.fromHex(
        "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
      )
      local u = util.fromHex(
        "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
      )
      local expected =
        "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
      local actual = util.toHex(curve25519.x25519(scalar, u))

      assert.are.equal(expected, actual)
    end)

    test("DH", function()
      local alicePriv = util.fromHex(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
      )
      local alicePub = util.fromHex(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
      )

      assert.are.equal(
        util.toHex(alicePub),
        util.toHex(curve25519.x25519(alicePriv, curve25519.nine))
      )

      local bobPriv = util.fromHex(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
      )
      local bobPub = util.fromHex(
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
      )

      assert.are.equal(
        util.toHex(bobPub),
        util.toHex(curve25519.x25519(bobPriv, curve25519.nine))
      )

      local sharedSecret = util.fromHex(
        "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
      )

      local aliceSecret = curve25519.deriveSharedSecret(
        {private = alicePriv}, {public = bobPub}
      )
      assert.are.equal(util.toHex(sharedSecret), util.toHex(aliceSecret))

      local bobSecret = curve25519.deriveSharedSecret(
        {private = bobPriv}, {public = alicePub}
      )
      assert.are.equal(util.toHex(sharedSecret), util.toHex(bobSecret))
    end)
  end)

  context("Project Wycheproof test vectors #wycheproof", function()
    testUtil.makeWycheproofTests {
      file = "x25519_test.json",

      groupName = function(testGroup)
        return testGroup.curve
      end,

      prepareTestData = function(testSpec)
        return {
          flags = util.sequenceToMap(testSpec.flags, function(k) return k end),
        }
      end,

      runTest = function(testSpec, _, _, testData)
        local shouldAccept =
          testSpec.result == "valid"
          or testSpec.result == "acceptable"
            and not testData.flags.LowOrderPublic
            and not testData.flags.SmallPublicKey
            and not testData.flags.ZeroSharedSecret

        local pubKey = util.fromHex(testSpec.public)
        local privKey = util.fromHex(testSpec.private)
        local shared = testSpec.shared

        local result, err = curve25519.deriveSharedSecret(
          {private = privKey}, {public = pubKey}
        )
        result = result and util.toHex(result)

        if shouldAccept then
          assert.are.equal(shared, result)
        else
          assert.is.Nil(result)
        end
      end,
    }
  end)
end)

local util = require("tls13.util")

local testUtil = require("test.test-util")(_ENV)

context("ChaCha20-Poly1305 tests #crypto #chacha20poly1305", function()
  local chacha20poly1305 = require("tls13.crypto.cipher.chacha20-poly1305")

  context("RFC 8439 test vectors", function()
    test("ChaCha20 quarter round test vector (§2.1.1)", function()
      local a = 0x11111111
      local b = 0x01020304
      local c = 0x9b8d6f43
      local d = 0x01234567

      assert:add_formatter(function(arg)
        if type(arg) == "number" then
          return ("0x%08x"):format(arg)
        end
      end)

      a, b, c, d = chacha20poly1305.chacha20QuarterRound(a, b, c, d)
      assert.are.equal(a, 0xea2a92f4, "a")
      assert.are.equal(b, 0xcb1cf8ce, "b")
      assert.are.equal(c, 0x4581472e, "c")
      assert.are.equal(d, 0x5881c4bb, "d")
    end)

    test("ChaCha20 block function test vector (§2.3.2)", function()
      local key = util.fromHex(
        "000102030405060708090a0b0c0d0e0f\z
          101112131415161718191a1b1c1d1e1f"
      )
      local nonce = util.fromHex("000000090000004a00000000")
      local expected = util.fromHex(
        "10f1e7e4d13b5915500fdd1fa32071c4\z
          c7d1f4c733c068030422aa9ac3d46c4e\z
          d2826446079faa0914c2d705d98b02a2\z
          b5129cd1de164eb9cbd083e8a2503c4e"
      )

      local actual = chacha20poly1305.chacha20Block(key, 1, nonce)
      assert.are.equal(util.toHex(expected), util.toHex(actual))
    end)

    test("ChaCha20 cipher test vector (§2.4.2)", function()
      local key = util.fromHex(
        "000102030405060708090a0b0c0d0e0f\z
          101112131415161718191a1b1c1d1e1f"
      )
      local nonce = util.fromHex("000000000000004a00000000")
      local plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you \z
          only one tip for the future, sunscreen would be it."
      local expected = util.fromHex(
        "6e2e359a2568f98041ba0728dd0d6981\z
          e97e7aec1d4360c20a27afccfd9fae0b\z
          f91b65c5524733ab8f593dabcd62b357\z
          1639d624e65152ab8f530c359f0861d8\z
          07ca0dbf500d6a6156a38e088a22b65e\z
          52bc514d16ccf806818ce91ab7793736\z
          5af90bbf74a35be6b40b8eedf2785e42\z
          874d"
      )

      local actual = chacha20poly1305.chacha20:encrypt(plaintext, key, nonce, 1)
      assert.are.equal(util.toHex(expected), util.toHex(actual))
    end)

    test("Poly1305 test vector (§2.5.2)", function()
      local key = util.fromHex(
        "85d6be7857556d337f4452fe42d506a8\z
          0103808afb0db2fd4abff6af4149f51b"
      )
      local message = "Cryptographic Forum Research Group"
      local expected = util.fromHex("a8061dc1305136c6c22b8baf0c0127a9")

      local actual = chacha20poly1305.poly1305(message, key)
      assert.are.equal(util.toHex(expected), util.toHex(actual))
    end)

    test("Poly1305 key generation test vector (§2.6.2)", function()
      local key = util.fromHex(
        "808182838485868788898a8b8c8d8e8f\z
          909192939495969798999a9b9c9d9e9f"
      )
      local nonce = util.fromHex("000000000001020304050607")
      local expected = util.fromHex(
        "8ad5a08b905f81cc815040274ab29471\z
          a833b637e3fd0da508dbb8e2fdd1a646"
      )

      local actual = chacha20poly1305.poly1305KeyGen(key, nonce)
      assert.are.equal(util.toHex(expected), util.toHex(actual))
    end)

    test("ChaCha20-Poly1305 AEAD test vector (§2.8.2)", function()
      local key = util.fromHex(
        "808182838485868788898a8b8c8d8e8f\z
          909192939495969798999a9b9c9d9e9f"
      )
      local plaintext =
        "Ladies and Gentlemen of the class of '99: If I could offer you \z
          only one tip for the future, sunscreen would be it."
      local aad = util.fromHex("50515253c0c1c2c3c4c5c6c7")
      local iv = util.fromHex("070000004041424344454647")
      local expected = util.fromHex(
        "d31a8d34648e60db7b86afbc53ef7ec2\z
          a4aded51296e08fea9e2b5a736ee62d6\z
          3dbea45e8ca9671282fafb69da92728b\z
          1a71de0a9e060b2905d6a5b67ecd3b36\z
          92ddbd7f2d778b8c9803aee328091b58\z
          fab324e4fad675945585808b4831d7bc\z
          3ff4def08e4b7a9de576d26586cec64b\z
          61161ae10b594f09e26a7e902ecbd060\z
          0691"
      )

      local aead = chacha20poly1305.chacha20Poly1305(key)
      local actual = aead:encrypt(plaintext, iv, aad)
      assert.are.equal(util.toHex(expected), util.toHex(actual))

      local decryptResult = {aead:decrypt(expected, iv, aad)}
      assert.are.same({plaintext}, decryptResult)
    end)
  end)

  context("Project Wycheproof test vectors", function()
    testUtil.makeWycheproofTests {
      file = "chacha20_poly1305_test.json",

      groupName = function(testGroup)
        return ("IV size: %d, key size: %d, tag size: %d"):format(
          testGroup.ivSize, testGroup.keySize, testGroup.tagSize
        )
      end,

      prepareGroupData = function(testGroup)
        local ivSizeValid = testGroup.ivSize == 96

        return {ivSizeValid = ivSizeValid}
      end,

      runTest = function(testSpec, testGroup, groupData)
        local key = util.fromHex(testSpec.key)
        local iv = util.fromHex(testSpec.iv)
        local aad = util.fromHex(testSpec.aad)
        local plaintext = util.fromHex(testSpec.msg)
        local ciphertext = util.fromHex(testSpec.ct)
        local tag = util.fromHex(testSpec.tag)

        local aead = chacha20poly1305.chacha20Poly1305(key)

        if testSpec.result == "valid" then
          local actual = aead:encrypt(plaintext, iv, aad)
          assert.are.equal(util.toHex(ciphertext .. tag), util.toHex(actual))
        end

        local function getResult()
          return aead:decrypt(ciphertext .. tag, iv, aad)
        end

        if testSpec.result == "valid" then
          local actual = getResult()

          if actual then
            actual = util.toHex(actual)
          end

          assert.are.equal(util.toHex(plaintext), actual)
        elseif not groupData.ivSizeValid then
          assert.has.errors(getResult)
        else
          assert.is.Nil((getResult()))
        end
      end,
    }
  end)
end)

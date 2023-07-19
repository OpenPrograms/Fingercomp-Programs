local util = require("tls13.util")

local testUtil = require("test.test-util")(_ENV)

context("NIST P-384 tests #crypto #secp384r1", function()
  local secp384r1 = require("tls13.crypto.secp384r1")
  local sigalg = require("tls13.sigalg")

  context("Field operations", function()
    test("fieldMul", function()
      local a = {
        0x15d1b6e7, 0x3cb1027b, 0x0b2a28e3, 0x03869875, 0x036a1c03,
        0x00f55afc, 0x24350f40, 0x008586a7, 0x15de10c9, 0x2cb99a1e,
        0x2a93cafa, 0x24da6a20, 0xc43dff,
      }
      local b = {
        0x347238f7, 0x2b81de15, 0x38f33a0a, 0x2e800886, 0x358d90a0,
        0x36d4d820, 0x3db2dab6, 0x28e907c8, 0x340c2256, 0x0fe960f4,
        0x12727022, 0x12f7ac66, 0xcef8d4,
      }
      local expected = {
        0x18dbb537, 0x0c22c8e2, 0x1d6f903e, 0x16cfd28a, 0x1aa44b5a,
        0x17f136c9, 0x0d51f238, 0x1a3f23cd, 0x1a8f1294, 0x2f25c5c5,
        0x1fa767ae, 0x01c37483, 0x1186f7
      }

      local actual = {}
      secp384r1.field.fieldMul(actual, a, b)
      secp384r1.field.fieldReduceQuick(actual, actual)

      assert.are.same(expected, actual)
    end)
  end)

  context("Scalar field operations", function()
    test("Element inversion", function()
      local element = {
        0x0d82b9f1, 0x33fd53bb, 0x18ac7aa9, 0x2fd8826d, 0x09513805,
        0x28c09038, 0x0a03995c, 0x3b8ea353, 0x3b8c2574, 0x12175504,
        0x0f8900cf, 0x27f074be, 0x1840da,
      }
      local expected = {
        0x05ed94c5, 0x3f0673d6, 0x2d358e9c, 0x0faf5edd, 0x31e7cd6d,
        0x23971172, 0x2802ae76, 0x31c63060, 0x348551ff, 0x0b18b733,
        0x0e24a151, 0x170d9167, 0x5f4851,
      }
      local actual = {}

      secp384r1.scalar.scalarInvert(actual, element)
      secp384r1.scalar.scalarReduceQuick(actual, actual)
      assert.are.same(expected, actual)

      secp384r1.scalar.scalarSub(actual, actual, expected)
      assert.is.True(secp384r1.scalar.scalarIsZero(actual))
    end)

    test("scalarMul", function()
      local a = {
        0x1b523b17, 0x336713d3, 0x3b2c51d9, 0x36ec53bf, 0x259ce9b8,
        0x3e3ffc99, 0x3bdd6fd7, 0x0bb17202, 0x0e913f4a, 0x24987b7a,
        0x185ae643, 0x1151ca28, 0xb97200,
      }
      local b = {
        0x12ccc4a6, 0x1f45872e, 0x12afb80b, 0x37a94a18, 0x1a4e073c,
        0x1e199119, 0x1e7f17c5, 0x3c522e30, 0x0fc6f967, 0x2630aeca,
        0x2e7742c4, 0x1370e964, 0xea0428,
      }
      local expected = {
        0x1eb048eb, 0x2c87d8f1, 0x16480caa, 0x168af87b, 0x3a454ecf,
        0x2dfddee4, 0x12ee7cd8, 0x2cac72dc, 0x0a06a3a3, 0x089cbad1,
        0x0e09a310, 0x292fbf40, 0x875e67,
      }

      local actual = {}
      secp384r1.scalar.scalarMul(actual, a, b)
      secp384r1.scalar.scalarReduceQuick(actual, actual)
      assert.are.same(expected, actual)
    end)
  end)

  test("scalarSub", function()
    local a = {
      0x00000002, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000,
      0x00000000, 0x00000000, 0x000000,
    }
    local b = {
      0x0cc52975, 0x33b065ab, 0x0b0a77ae, 0x06836c92, 0x372ddf58,
      0x0d3607d0, 0x3ffffc76, 0x3fffffff, 0x3fffffff, 0x3fffffff,
      0x3fffffff, 0x3fffffff, 0xffffff,
    }
    local expected = secp384r1.scalar.scalarZero()

    local actual = {}
    secp384r1.scalar.scalarSub(actual, a, b)
    secp384r1.scalar.scalarReduceQuick(actual, actual)
    assert.are.same(expected, actual)
  end)

  context("EC group operations", function()
    local f = io.open("test/data/ec.json", "r")
    local encodedTests = f:read("a")
    f:close()

    local tests = testUtil.json.decode(encodedTests)

    local function decodePoint(point)
      local x = secp384r1.field.fieldFromBytes(util.fromHex(point.x))
      local y = secp384r1.field.fieldFromBytes(util.fromHex(point.y))
      local z

      if point.z then
        z = secp384r1.field.fieldFromBytes(util.fromHex(point.z))
      elseif point.zero then
        z = secp384r1.field.fieldZero()
      else
        z = secp384r1.field.fieldOne()
      end

      return {x, y, z}
    end

    test("Point decoding", function()
      local encoded = util.fromHex(
        "04503269221ca88551650426a1772d6473232f4a23510cc9ca\z
          dc70419ea50c01eee1fa391177fde574ca1664de7ff0bbb8\z
          7a99e0b8058ceb8024476ab02704e47af27087582af77411\z
          44651dfd6810263fdcca9c03069870c7f1df05dcbfd7de62"
      )
      local expected = {
        {
          0x3ff0bbb8, 0x28599379, 0x3fde574c, 0x3e8e445d, 0x0c01eee1,
          0x01067a94, 0x0c9cadc7, 0x1288d443, 0x2473232f, 0x1a85dcb5,
          0x15165042, 0x08872a21, 0x503269,
        },
        {
          0x3fd7de62, 0x077c1772, 0x29870c7f, 0x32a700c1, 0x10263fdc,
          0x1477f5a0, 0x37411446, 0x21d60abd, 0x247af270, 0x2ac09c13,
          0x38024476, 0x2e01633a, 0x7a99e0,
        },
        secp384r1.field.fieldOne(),
      }

      local actual = secp384r1.group.groupJacobianZero()
      assert(secp384r1.group.groupJacobianFromBytes(actual, encoded))
      assert.are.same(expected, actual)
    end)

    context("Point addition", function()
      for _, testSpec in ipairs(tests["jacobian-add"]) do
        test(("Test %d: %s"):format(testSpec.id, testSpec.name), function()
          local lhs = decodePoint(testSpec.lhs)
          local rhs = decodePoint(testSpec.rhs)
          local result = decodePoint(testSpec.result)

          local actual = secp384r1.group.groupJacobianZero()
          secp384r1.group.groupJacobianAdd(actual, lhs, rhs)
          secp384r1.group.groupJacobianSub(actual, actual, result)

          assert.are.equal(1, secp384r1.group.groupJacobianZeroFlag(actual))
        end)
      end
    end)

    context("Point addition, Z = 1", function()
      for _, testSpec in ipairs(tests["mixed-add"]) do
        test(("Test %d: %s"):format(testSpec.id, testSpec.name), function()
          local lhs = decodePoint(testSpec.lhs)
          local rhs = decodePoint(testSpec.rhs)
          local result = decodePoint(testSpec.result)

          local actual = secp384r1.group.groupJacobianZero()
          secp384r1.group.groupJacobianMixedAdd(actual, lhs, rhs)
          secp384r1.group.groupJacobianSub(actual, actual, result)

          assert.are.equal(1, secp384r1.group.groupJacobianZeroFlag(actual))
        end)
      end
    end)

    context("Scalar multiplication precomputation", function()
      local p = {
        {
          0x17bbd1b5, 0x13d00593, 0x0ec1e7f8, 0x1923a6b5, 0x3bafc869,
          0x2f912e87, 0x1cb8dcef, 0x03803bc4, 0x3fb3b274, 0x104a60d0,
          0x03ce372f, 0x251dffef, 0x0591c5,
        },
        {
          0x2a876576, 0x3538bb6a, 0x3011e553, 0x1a2e32fb, 0x221fb853,
          0x2a9a575b, 0x2d2cadb5, 0x20edf35d, 0x39189c3f, 0x0c291e0c,
          0x27b2cefc, 0x2658af81, 0x07ea69,
        },
        secp384r1.field.fieldOne(),
      }

      local precomp = secp384r1.group.groupDoScalarMultPrecomputation(p)
      local q = secp384r1.group.groupJacobianZero()

      for i = 1, 31, 1 do
        secp384r1.group.groupJacobianMixedAdd(q, q, p)

        if i % 2 == 1 then
          local idx = i // 2 + 1
          local check = secp384r1.group.groupJacobianZero()
          secp384r1.group.groupJacobianSub(check, q, precomp[idx])

          assert.are.equal(1, secp384r1.group.groupJacobianZeroFlag(check))
        end
      end
    end)

    context("Double-base scalar multiplication", function()
      for _, testSpec in ipairs(tests["double-base-mul"]) do
        test(("Test %d: %s"):format(testSpec.id, testSpec.name), function()
          local p = decodePoint(testSpec.p)
          local u = secp384r1.scalar.scalarFromBytes(util.fromHex(testSpec.u))
          local v = secp384r1.scalar.scalarFromBytes(util.fromHex(testSpec.v))
          local result = decodePoint(testSpec.result)

          assert.is.table(u)
          assert.is.table(v)

          local actual = secp384r1.group.groupJacobianZero()
          secp384r1.group.groupJacobianDoubleBaseScalarMulAdd(actual, p, u, v)
          assert.are.equal(
            secp384r1.group.groupJacobianZeroFlag(result),
            secp384r1.group.groupJacobianZeroFlag(actual)
          )
          secp384r1.group.groupJacobianSub(actual, actual, result)

          assert.are.equal(1, secp384r1.group.groupJacobianZeroFlag(actual))
        end)
      end
    end)
  end)

  context("ECDSA verification #ecdsa #ecdsaSha384", function()
    context("Project Wycheproof test vectors", function()
      local function checkSignature(publicKey, message, signature)
        local sr, ss = sigalg.decodeEcdsaSignature(signature)

        if not sr then
          return sr, ss
        end

        return secp384r1.ecdsaVerifySha384(message, sr, ss, publicKey)
      end

      testUtil.makeWycheproofTests {
        file = "ecdsa_secp384r1_sha384_test.json",

        groupName = function(testGroup)
          return ("Curve: %s, hash: %s")
            :format(testGroup.key.curve, testGroup.sha)
        end,

        runTest = function(testSpec, testGroup)
          local publicKey = util.fromHex(testGroup.key.uncompressed)
          local message = util.fromHex(testSpec.msg)
          local signature = util.fromHex(testSpec.sig)

          local valid, err = checkSignature(publicKey, message, signature)

          if testSpec.result == "valid" then
            assert.are.same({true}, {valid, err})
          else
            assert.is.falsy(valid)
          end
        end,
      }
    end)
  end)
end)

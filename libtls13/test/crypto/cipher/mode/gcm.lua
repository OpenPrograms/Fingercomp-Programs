local util = require("util")

context("AES-GCM tests #crypto #cipher #gcm #aes", function()
  local aes = require("crypto.cipher.aes")
  local gcm = require("crypto.cipher.mode.gcm")

  local aes128Gcm = gcm.gcm(aes.aes128)
  local aes256Gcm = gcm.gcm(aes.aes256)

  local function check(args)
    local gcm = args.gcm
    local key = util.fromHex(args.key)
    local iv = util.fromHex(args.iv)
    local aad = util.fromHex(args.aad)
    local plaintext = util.fromHex(args.plaintext)
    local ciphertext = util.fromHex(args.ciphertext)
    local tag = util.fromHex(args.tag)

    local keyedGcm = gcm(key)
    local actualCiphertext, actualTag = keyedGcm:encrypt(plaintext, iv, aad)

    assert.are.equal(
      util.toHex(ciphertext), util.toHex(actualCiphertext),
      "invalid ciphertext"
    )
    assert.are.equal(
      util.toHex(tag), util.toHex(actualTag),
      "invalid tag"
    )
    assert.are.equal(#ciphertext, keyedGcm:getLength(#plaintext, #aad))

    local actualPlaintext = keyedGcm:decrypt(ciphertext, tag, iv, aad)
    assert.are.equal(
      util.toHex(plaintext), util.toHex(actualPlaintext),
      "invalid plaintext"
    )
  end

  local function checkOctoWords(expectedHi, expectedLo, actualHi, actualLo)
    assert.are.equal(
      ("%016x %016x"):format(expectedHi, expectedLo),
      ("%016x %016x"):format(actualHi, actualLo)
    )
  end

  test("multiplication by x", function()
    checkOctoWords(
      0x0000000000000000, 0x0000000000000000,
      gcm.__internal.mulx(0x0000000000000000, 0x0000000000000000)
    )

    checkOctoWords(
      0x123456789abcdeff >> 1, 0xfedcba9876543210 >> 1 | 1 << 63,
      gcm.__internal.mulx(0x123456789abcdeff, 0xfedcba9876543210)
    )

    checkOctoWords(
      0xfedcba987654321f >> 1 ~ 0xe1 << 56, 0x89abcdef01234567 >> 1 ~ 1 << 63,
      gcm.__internal.mulx(0xfedcba987654321f, 0x89abcdef01234567)
    )
  end)

  context("polynomial multiplication in GF(2¹²⁸)", function()
    local mul128 = gcm.__internal.mul128

    -- a slow but robust and general 128-bit little-endian polynomial
    -- multiplication algorithm
    local function slowMul128(hi1, lo1, hi2, lo2)
      local hi, lo = 0, 0

      for i = 1, 128, 1 do
        if hi2 >> 63 == 1 then
          hi = hi ~ hi1
          lo = lo ~ lo1
        end

        local carry = lo1 & 1
        lo1 = lo1 >> 1 | hi1 << 63
        hi1 = hi1 >> 1 ~ -carry & 0xe1 << 56

        hi2 = hi2 << 1 | lo2 >> 63
        lo2 = lo2 << 1
      end

      return hi, lo
    end

    local function checkMul(lut, hi1, lo1, hi2, lo2)
      local expectedHi, expectedLo = slowMul128(hi1, lo1, hi2, lo2)

      checkOctoWords(expectedHi, expectedLo, mul128(lut, hi2, lo2))
    end

    test("h = 0¹²⁸", function()
      local lut = gcm.__internal.computeMulLut(0, 0)

      checkOctoWords(
        0x0000000000000000, 0x0000000000000000,
        mul128(lut, 0x0000000000000000, 0x0000000000000000)
      )
      checkOctoWords(
        0x0000000000000000, 0x0000000000000000,
        mul128(lut, 0x123456789abcdef0, 0xfedcba987654321f)
      )
    end)

    test("h = 1¹²⁸", function()
      local lut = gcm.__internal.computeMulLut(-1, -1)

      checkOctoWords(0, 0, mul128(lut, 0, 0))
      checkOctoWords(-1, -1, mul128(lut, 1 << 63, 0))
      checkMul(lut, -1, -1, 0xfedcba987654321f, 0x89abcdef01234567)
    end)

    test("h = <random>", function()
      local hi1, lo1 =
        (">I8I8"):unpack(util.fromHex("577e0de80bd416bbff9be663a286281e"))
      local hi2, lo2 =
        (">I8I8"):unpack(util.fromHex("7fed05cfa1d4b5fc98a39e8286ba6bb1"))

      checkMul(
        gcm.__internal.computeMulLut(hi1, lo1),
        hi1, lo1,
        hi2, lo2
      )
    end)

    test("h from the paper's test case 2", function()
      local hi1, lo1 =
        (">I8I8"):unpack(util.fromHex("66e94bd4ef8a2c3b884cfa59ca342b2e"))
      local hi2, lo2 =
        (">I8I8"):unpack(util.fromHex("0388dace60b6a392f328c2b971b2fe78"))
      local lut = gcm.__internal.computeMulLut(hi1, lo1)

      checkMul(lut, hi1, lo1, hi2, lo2)
      assert.are.equal(
        "5e2ec746917062882c85b0685353deb7",
        ("%016x%016x"):format(gcm.__internal.mul128(lut, hi2, lo2))
      )
    end)
  end)

  context("GHASH", function()
    test("the paper's test case 2", function()
      local lut =
        gcm.__internal.computeMulLut(0x66e94bd4ef8a2c3b, 0x884cfa59ca342b2e)
      local block = util.fromHex(
        "0388dace60b6a392f328c2b971b2fe78\z
        00000000000000000000000000000080"
      )

      assert.are.equal(
        "f38cbb1ad69223dcc3457ae5b6b0f885",
        ("%016x%016x"):format(gcm.__internal.ghash(block, lut))
      )
    end)

    test("the paper's test case 3", function()
      local lut =
        gcm.__internal.computeMulLut(0xb83b533708bf535d, 0x0aa6e52980d53b78)
      local block = util.fromHex(
        "42831ec2217774244b7221b784d0d49c\z
        e3aa212f2c02a4e035c17e2329aca12e\z
        21d514b25466931c7d8f6a5aac84aa05\z
        1ba30b396a0aac973d58e091473f5985\z
        00000000000000000000000000000200"
      )

      assert.are.equal(
        "7f1b32b81b820d02614f8895ac1d4eac",
        ("%016x%016x"):format(gcm.__internal.ghash(block, lut))
      )
    end)
  end)

  test("NIST test vectors, AES128", function()
    check {
      gcm = aes128Gcm,
      key = "feffe9928665731c6d6a8f9467308308",
      iv = "cafebabefacedbaddecaf888",
      aad = "",
      plaintext = "",

      ciphertext = "",
      tag = "3247184b3c4f69a44dbcd22887bbb418",
    }

    check {
      gcm = aes128Gcm,
      key = "feffe9928665731c6d6a8f9467308308",
      iv = "cafebabefacedbaddecaf888",
      aad = "",
      plaintext =
        "d9313225f88406e5a55909c5aff5269a\z
        86a7a9531534f7da2e4c303d8a318a72\z
        1c3c0c95956809532fcf0e2449a6b525\z
        b16aedf5aa0de657ba637b391aafd255",

      ciphertext =
        "42831ec2217774244b7221b784d0d49c\z
        e3aa212f2c02a4e035c17e2329aca12e\z
        21d514b25466931c7d8f6a5aac84aa05\z
        1ba30b396a0aac973d58e091473f5985",
      tag = "4d5c2af327cd64a62cf35abd2ba6fab4",
    }

    check {
      gcm = aes128Gcm,
      key = "feffe9928665731c6d6a8f9467308308",
      iv = "cafebabefacedbaddecaf888",
      aad =
        "3ad77bb40d7a3660a89ecaf32466ef97\z
        f5d3d58503b9699de785895a96fdbaaf\z
        43b1cd7f598ece23881b00e3ed030688\z
        7b0c785e27e8ad3f8223207104725dd4",
      plaintext = "",

      ciphertext = "",
      tag = "5f91d77123ef5eb9997913849b8dc1e9",
    }

    check {
      gcm = aes128Gcm,
      key = "feffe9928665731c6d6a8f9467308308",
      iv = "cafebabefacedbaddecaf888",
      aad =
        "3ad77bb40d7a3660a89ecaf32466ef97\z
        f5d3d58503b9699de785895a96fdbaaf\z
        43b1cd7f598ece23881b00e3ed030688\z
        7b0c785e27e8ad3f8223207104725dd4",
      plaintext =
        "d9313225f88406e5a55909c5aff5269a\z
        86a7a9531534f7da2e4c303d8a318a72\z
        1c3c0c95956809532fcf0e2449a6b525\z
        b16aedf5aa0de657ba637b391aafd255",

      ciphertext =
        "42831ec2217774244b7221b784d0d49c\z
        e3aa212f2c02a4e035c17e2329aca12e\z
        21d514b25466931c7d8f6a5aac84aa05\z
        1ba30b396a0aac973d58e091473f5985",
      tag = "64c0232904af398a5b67c10b53a5024d",
    }

    check {
      gcm = aes128Gcm,
      key = "feffe9928665731c6d6a8f9467308308",
      iv = "cafebabefacedbaddecaf888",
      aad = "3ad77bb40d7a3660a89ecaf32466ef97f5d3d585",
      plaintext =
        "d9313225f88406e5a55909c5aff5269a\z
        86a7a9531534f7da2e4c303d8a318a72\z
        1c3c0c95956809532fcf0e2449a6b525\z
        b16aedf5aa0de657ba637b39",

      ciphertext =
        "42831ec2217774244b7221b784d0d49c\z
        e3aa212f2c02a4e035c17e2329aca12e\z
        21d514b25466931c7d8f6a5aac84aa05\z
        1ba30b396a0aac973d58e091",
      tag = "f07c2528eea2fca1211f905e1b6a881b",
    }
  end)

  context("Project Wycheproof test vectors", function()
    local aesGcm = {
      [128] = aes128Gcm,
      [256] = aes256Gcm,
    }

    local function makeWycheproofTest(group, testSpec)
      return function()
        local keyedGcm = aesGcm[group.keySize](util.fromHex(testSpec.key))
        local plaintext = util.fromHex(testSpec.msg)
        local iv = util.fromHex(testSpec.iv)
        local aad = util.fromHex(testSpec.aad)
        local ciphertext = util.fromHex(testSpec.ct)
        local tag = util.fromHex(testSpec.tag)

        if testSpec.result == "valid" or testSpec.result == "acceptable" then
          local actualCiphertext, actualTag = keyedGcm:encrypt(
            plaintext,
            iv,
            aad
          )

          assert.are.equal(
            util.toHex(ciphertext), util.toHex(actualCiphertext),
            "invalid ciphertext"
          )
          assert.are.equal(
            util.toHex(tag), util.toHex(actualTag),
            "invalid tag"
          )

          local actualPlaintext = keyedGcm:decrypt(ciphertext, tag, iv, aad)
          assert.are.equal(util.toHex(plaintext), util.toHex(actualPlaintext))
        else
          local result = keyedGcm:decrypt(ciphertext, tag, iv, aad)
          assert.is_nil(result)
        end
      end
    end

    -- eh.
    local json = dofile("third-party/json.lua/json.lua")

    local f =
      io.open("third-party/wycheproof/testvectors/aes_gcm_test.json", "r")
    local aesGcmTestJson = f:read("a")
    f:close()

    local data = json.decode(aesGcmTestJson)

    for _, group in ipairs(data.testGroups) do
      if group.tagSize == 128
          and group.keySize ~= 192
          and group.ivSize == 96 then
        local label =
          ("IV size = %d, key size = %d"):format(group.ivSize, group.keySize)

        context(label, function()
          for _, testSpec in ipairs(group.tests) do
            local testName = ("Test %d%s"):format(
              testSpec.tcId,
              testSpec.comment == "" and "" or ": " .. testSpec.comment
            )

            test(testName, makeWycheproofTest(group, testSpec))
          end
        end)
      end
    end
  end)
end)

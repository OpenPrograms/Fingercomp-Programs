local util = require("tls13.util")
local testUtil = require("test.test-util")(_ENV)

context("HMAC tests #crypto #hmac", function()
  local hmac = require("crypto.hmac")
  local sha2 = require("crypto.hash.sha2")

  local hmacSha256 = hmac.hmac(sha2.sha256)
  local hmacSha384 = hmac.hmac(sha2.sha384)
  local hmacSha512 = hmac.hmac(sha2.sha512)

  local function check(args)
    local hmac = args.hmac
    local input = args.input
    local key = args.key
    local mac = args.mac
    local invalid = args.invalid

    key = util.fromHex(key)
    local actualMac = hmac(input, key):sub(1, args.truncate or -1)

    if invalid then
      assert.are.Not.equal(mac, util.toHex(actualMac))
    else
      assert.are.equal(mac, util.toHex(actualMac))
    end
  end

  test("NIST test vectors, SHA256", function()
    check {
      hmac = hmacSha256,
      input = "Sample message for keylen=blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f",
      mac = "8bb9a1db9806f20df7f77b82138c7914d174d59e13dc4d0169c9057b133e1d62",
    }

    check {
      hmac = hmacSha256,
      input = "Sample message for keylen<blocklen",
      key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      mac = "a28cf43130ee696a98f14a37678b56bcfcbdd9e5cf69717fecf5480f0ebdf790",
    }

    check {
      hmac = hmacSha256,
      input = "Sample message for keylen<blocklen, with truncated tag",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f30",
      truncate = 16,
      mac = "27a8b157839efeac98df070b331d5936",
    }
  end)

  test("NIST test vectors, SHA384", function()
    check {
      hmac = hmacSha384,
      input = "Sample message for keylen=blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f\z
        404142434445464748494a4b4c4d4e4f\z
        505152535455565758595a5b5c5d5e5f\z
        606162636465666768696a6b6c6d6e6f\z
        707172737475767778797a7b7c7d7e7f",
      mac =
        "63c5daa5e651847ca897c95814ab830bededc7d25e83eef9\z
        195cd45857a37f448947858f5af50cc2b1b730ddf29671a9",
    }

    check {
      hmac = hmacSha384,
      input = "Sample message for keylen<blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f1011121314151617\z
        18191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f",
      mac =
        "6eb242bdbb582ca17bebfa481b1e23211464d2b7f8c20b9f\z
        f2201637b93646af5ae9ac316e98db45d9cae773675eeed0",
    }

    check {
      hmac = hmacSha384,
      input = "Sample message for keylen=blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f\z
        404142434445464748494a4b4c4d4e4f\z
        505152535455565758595a5b5c5d5e5f\z
        606162636465666768696a6b6c6d6e6f\z
        707172737475767778797a7b7c7d7e7f\z
        808182838485868788898a8b8c8d8e8f\z
        909192939495969798999a9b9c9d9e9f\z
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\z
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\z
        c0c1c2c3c4c5c6c7",
      mac =
        "5b664436df69b0ca22551231a3f0a3d5b4f97991713cfa84\z
        bff4d0792eff96c27dccbbb6f79b65d548b40e8564cef594",
    }

    check {
      hmac = hmacSha384,
      input = "Sample message for keylen<blocklen, with truncated tag",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f30",
      truncate = 24,
      mac = "c48130d3df703dd7cdaa56800dfbd2ba2458320e6e1f98fe",
    }
  end)

  test("NIST test vectors, SHA512", function()
    check {
      hmac = hmacSha512,
      input = "Sample message for keylen=blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f\z
        404142434445464748494a4b4c4d4e4f\z
        505152535455565758595a5b5c5d5e5f\z
        606162636465666768696a6b6c6d6e6f\z
        707172737475767778797a7b7c7d7e7f",
      mac =
        "fc25e240658ca785b7a811a8d3f7b4ca\z
        48cfa26a8a366bf2cd1f836b05fcb024\z
        bd36853081811d6cea4216ebad79da1c\z
        fcb95ea4586b8a0ce356596a55fb1347",
    }

    check {
      hmac = hmacSha512,
      input = "Sample message for keylen<blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f",
      mac =
        "fd44c18bda0bb0a6ce0e82b031bf2818\z
        f6539bd56ec00bdc10a8a2d730b3634d\z
        e2545d639b0f2cf710d0692c72a1896f\z
        1f211c2b922d1a96c392e07e7ea9fedc",
    }

    check {
      hmac = hmacSha512,
      input = "Sample message for keylen=blocklen",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f\z
        303132333435363738393a3b3c3d3e3f\z
        404142434445464748494a4b4c4d4e4f\z
        505152535455565758595a5b5c5d5e5f\z
        606162636465666768696a6b6c6d6e6f\z
        707172737475767778797a7b7c7d7e7f\z
        808182838485868788898a8b8c8d8e8f\z
        909192939495969798999a9b9c9d9e9f\z
        a0a1a2a3a4a5a6a7a8a9aaabacadaeaf\z
        b0b1b2b3b4b5b6b7b8b9babbbcbdbebf\z
        c0c1c2c3c4c5c6c7",
      mac =
        "d93ec8d2de1ad2a9957cb9b83f14e76a\z
        d6b5e0cce285079a127d3b14bccb7aa7\z
        286d4ac0d4ce64215f2bc9e6870b33d9\z
        7438be4aaa20cda5c5a912b48b8e27f3",
    }

    check {
      hmac = hmacSha512,
      input = "Sample message for keylen<blocklen, with truncated tag",
      key =
        "000102030405060708090a0b0c0d0e0f\z
        101112131415161718191a1b1c1d1e1f\z
        202122232425262728292a2b2c2d2e2f30",
      truncate = 32,
      mac = "00f3e9a77bb0f06de15f160603e42b5028758808596664c03e1ab8fb2b076778",
    }
  end)

  context("Project Wycheproof test vectors", function()
    local function wycheproofTests(file, hashName, hmac)
      testUtil.makeWycheproofTests {
        file = file,

        groupName = function(testGroup)
          return ("%s, key size: %d, mac size: %d"):format(
            hashName,
            testGroup.keySize,
            testGroup.tagSize
          )
        end,

        runTest = function(testSpec, testGroup)
          check {
            hmac = hmac,
            input = util.fromHex(testSpec.msg),
            key = testSpec.key,
            mac = testSpec.tag,
            truncate = testGroup.tagSize // 8,
            invalid = testSpec.result == "invalid",
          }
        end,
      }
    end

    wycheproofTests("hmac_sha256_test.json", "sha256", hmacSha256)
    wycheproofTests("hmac_sha384_test.json", "sha384", hmacSha384)
    wycheproofTests("hmac_sha512_test.json", "sha512", hmacSha512)
  end)
end)

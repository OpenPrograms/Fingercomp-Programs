local util = require("tls13.util")
local testUtil = require("test.test-util")(_ENV)

context("HKDF tests #crypto #hkdf", function()
  local hmac = require("crypto.hmac")
  local hkdf = require("crypto.hkdf")
  local sha2 = require("crypto.hash.sha2")

  local hkdfSha256 = hkdf.hkdf(hmac.hmac(sha2.sha256))
  local hkdfSha384 = hkdf.hkdf(hmac.hmac(sha2.sha384))
  local hkdfSha512 = hkdf.hkdf(hmac.hmac(sha2.sha512))

  local function check(args)
    local hkdf = args.hkdf
    local ikm = args.ikm
    local salt = args.salt
    local context = args.context
    local len = args.len
    local okm = args.okm
    local invalid = args.invalid

    ikm = util.fromHex(ikm)
    salt = util.fromHex(salt)
    context = util.fromHex(context)
    okm = util.fromHex(okm)

    local key = hkdf:extract(ikm, salt)

    if invalid then
      assert.has.errors(function()
        return hkdf:expand(context, len, key)
      end)
    else
      local actualOkm = hkdf:expand(context, len, key)
      assert.are.equal(util.toHex(okm), util.toHex(actualOkm))
    end
  end

  context("Project Wycheproof test vectors", function()
    local function wycheproofTests(file, hashName, hkdf)
      testUtil.makeWycheproofTests {
        file = file,

        groupName = function(testGroup)
          return ("%s, key size: %d"):format(hashName, testGroup.keySize)
        end,

        runTest = function(testSpec, testGroup)
          check {
            hkdf = hkdf,
            ikm = testSpec.ikm,
            salt = testSpec.salt,
            context = testSpec.info,
            len = testSpec.size,
            okm = testSpec.okm,
            invalid = testSpec.result == "invalid",
          }
        end,
      }
    end

    wycheproofTests("hkdf_sha256_test.json", "sha256", hkdfSha256)
    wycheproofTests("hkdf_sha384_test.json", "sha384", hkdfSha384)
    wycheproofTests("hkdf_sha512_test.json", "sha512", hkdfSha512)
  end)
end)

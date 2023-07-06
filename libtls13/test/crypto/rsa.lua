local util = require("tls13.util")

local testUtil = require("test.test-util")(_ENV)

context("RSA signature tests #crypto #rsa", function()
  local oid = require("tls13.asn.oid")
  local rsa = require("tls13.crypto.rsa")
  local sha2 = require("tls13.crypto.hash.sha2")

  local hashSpecs = {
    ["SHA-256"] = {
      hash = sha2.sha256,
      oid = oid.hashalgs.sha256,
    },
    ["SHA-512"] = {
      hash = sha2.sha512,
      oid = oid.hashalgs.sha512,
    },
  }

  context("RSASSA-PKCS1-v1.5 signatures #pkcs1v15sig", function()
    context("Project Wycheproof test vectors", function()
      testUtil.makeWycheproofTests {
        file = "rsa_signature_test.json",

        prepareGroupData = function(testGroup)
          return {
            hashSpec = hashSpecs[testGroup.sha],
          }
        end,

        groupFilter = function(testGroup, groupData)
          return groupData.hashSpec ~= nil
        end,

        groupName = function(testGroup, groupData)
          return ("key size: %d, hash algorithm: %s"):format(
            testGroup.keysize,
            testGroup.sha
          )
        end,

        testFilter = function(testSpec)
          return testSpec.result ~= "acceptable"
        end,

        runTest = function(testSpec, testGroup, groupData)
          local hashSpec = groupData.hashSpec
          local pkcs1V15 = rsa.rsassaPkcs1V15(hashSpec.hash, hashSpec.oid)
          local pubKey =
            rsa.makePublicKeyFromHex(testGroup.n, testGroup.e)
          local message = util.fromHex(testSpec.msg)
          local signature = util.fromHex(testSpec.sig)

          local result, err = pkcs1V15:verify(pubKey, message, signature)

          if testSpec.result == "valid" then
            assert.is.Nil(err)
            assert.is.True(result)
          else
            assert.is.falsy(result)
          end
        end,
      }
    end)
  end)

  context("RSASSA-PSS signatures #psssig", function()
    local function wycheproofPssTest(file)
      testUtil.makeWycheproofTests {
        file = file,

        prepareGroupData = function(testGroup)
          return {
            hashSpec = hashSpecs[testGroup.sha],
            mgfHashSpec = hashSpecs[testGroup.mgfSha],
          }
        end,

        groupFilter = function(testGroup, groupData)
          return
            groupData.hashSpec ~= nil
            and groupData.mgfHashSpec ~= nil
            and testGroup.mgf == "MGF1"
        end,

        groupName = function(testGroup, groupData)
          return
            ("key size: %d, hash: %s, MGF: %s, MGF hash: %s, salt len: %d")
              :format(
                testGroup.keysize,
                testGroup.sha,
                testGroup.mgf,
                testGroup.mgfSha,
                testGroup.sLen
              )
        end,

        runTest = function(testSpec, testGroup, groupData)
          local hash = groupData.hashSpec.hash
          local mgfHash = groupData.mgfHashSpec.hash
          local mgf1 = rsa.mgf1(mgfHash)
          local pss = rsa.rsassaPss(hash, mgf1, testGroup.sLen)

          local pubKey =
            rsa.makePublicKeyFromHex(testGroup.n, testGroup.e)
          local message = util.fromHex(testSpec.msg)
          local signature = util.fromHex(testSpec.sig)

          if testSpec.result == "valid" then
            assert.is.True(pss:verify(pubKey, message, signature))
          else
            assert.is.False(pss:verify(pubKey, message, signature))
          end
        end,
      }
    end

    wycheproofPssTest("rsa_pss_2048_sha256_mgf1_0_test.json")
    wycheproofPssTest("rsa_pss_2048_sha256_mgf1_32_test.json")
    wycheproofPssTest("rsa_pss_2048_sha512_256_mgf1_28_test.json")
    wycheproofPssTest("rsa_pss_2048_sha512_256_mgf1_32_test.json")
    wycheproofPssTest("rsa_pss_3072_sha256_mgf1_32_test.json")
    wycheproofPssTest("rsa_pss_4096_sha256_mgf1_32_test.json")
    wycheproofPssTest("rsa_pss_4096_sha512_mgf1_32_test.json")
    wycheproofPssTest("rsa_pss_misc_test.json")
  end)
end)

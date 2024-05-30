local util = require("tls13.util")

local testUtil = require("test.test-util")(_ENV)

context("Curve25519 tests #crypto #curve25519", function()
  local curve25519 = require("tls13.crypto.curve25519")

  test("Field-to/from-bytes conversion", function()
    local bytes = ("x"):rep(32):gsub("().", string.char)
    local fe = curve25519.fieldFromBytes(bytes)

    assert.are.equal(
      util.toHex(bytes),
      util.toHex(curve25519.fieldToBytes(fe))
    )
  end)

  context("X25519 key exchange tests #x25519", function()
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
            flags =
              util.sequenceToMap(testSpec.flags, function(k) return k end),
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

  context("Ed25519 digital signature verification #ed25519", function()
    context("RFC 8032 test vectors", function()
      test("Test vector 1", function()
        local publicKey = util.fromHex(
          "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
        )
        local message = ""
        local signature = util.fromHex(
          "e5564300c360ac729086e2cc806e828a\z
          84877f1eb8e5d974d873e06522490155\z
          5fb8821590a33bacc61e39701cf9b46b\z
          d25bf5f0595bbe24655141438e7a100b"
        )

        assert.is.True(curve25519.verifyEd25519(publicKey, message, signature))
      end)

      test("Test vector 2", function()
        local publicKey = util.fromHex(
          "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c"
        )
        local message = util.fromHex("72")
        local signature = util.fromHex(
          "92a009a9f0d4cab8720e820b5f642540\z
          a2b27b5416503f8fb3762223ebdb69da\z
          085ac1e43e15996e458f3613d0f11d8c\z
          387b2eaeb4302aeeb00d291612bb0c00"
        )

        assert.is.True(curve25519.verifyEd25519(publicKey, message, signature))
      end)

      test("Test vector 3", function()
        local publicKey = util.fromHex(
          "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025"
        )
        local message = util.fromHex("af82")
        local signature = util.fromHex(
          "6291d657deec24024827e69c3abe01a3\z
          0ce548a284743a445e3680d7db5ac3ac\z
          18ff9b538d16f290ae67f760984dc659\z
          4a7c15e9716ed28dc027beceea1ec40a"
        )

        assert.is.True(curve25519.verifyEd25519(publicKey, message, signature))
      end)

      test("Test vector 1024", function()
        local publicKey = util.fromHex(
          "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
        )
        local message = util.fromHex(
          "08b8b2b733424243760fe426a4b54908\z
          632110a66c2f6591eabd3345e3e4eb98\z
          fa6e264bf09efe12ee50f8f54e9f77b1\z
          e355f6c50544e23fb1433ddf73be84d8\z
          79de7c0046dc4996d9e773f4bc9efe57\z
          38829adb26c81b37c93a1b270b20329d\z
          658675fc6ea534e0810a4432826bf58c\z
          941efb65d57a338bbd2e26640f89ffbc\z
          1a858efcb8550ee3a5e1998bd177e93a\z
          7363c344fe6b199ee5d02e82d522c4fe\z
          ba15452f80288a821a579116ec6dad2b\z
          3b310da903401aa62100ab5d1a36553e\z
          06203b33890cc9b832f79ef80560ccb9\z
          a39ce767967ed628c6ad573cb116dbef\z
          efd75499da96bd68a8a97b928a8bbc10\z
          3b6621fcde2beca1231d206be6cd9ec7\z
          aff6f6c94fcd7204ed3455c68c83f4a4\z
          1da4af2b74ef5c53f1d8ac70bdcb7ed1\z
          85ce81bd84359d44254d95629e9855a9\z
          4a7c1958d1f8ada5d0532ed8a5aa3fb2\z
          d17ba70eb6248e594e1a2297acbbb39d\z
          502f1a8c6eb6f1ce22b3de1a1f40cc24\z
          554119a831a9aad6079cad88425de6bd\z
          e1a9187ebb6092cf67bf2b13fd65f270\z
          88d78b7e883c8759d2c4f5c65adb7553\z
          878ad575f9fad878e80a0c9ba63bcbcc\z
          2732e69485bbc9c90bfbd62481d9089b\z
          eccf80cfe2df16a2cf65bd92dd597b07\z
          07e0917af48bbb75fed413d238f5555a\z
          7a569d80c3414a8d0859dc65a46128ba\z
          b27af87a71314f318c782b23ebfe808b\z
          82b0ce26401d2e22f04d83d1255dc51a\z
          ddd3b75a2b1ae0784504df543af8969b\z
          e3ea7082ff7fc9888c144da2af58429e\z
          c96031dbcad3dad9af0dcbaaaf268cb8\z
          fcffead94f3c7ca495e056a9b47acdb7\z
          51fb73e666c6c655ade8297297d07ad1\z
          ba5e43f1bca32301651339e22904cc8c\z
          42f58c30c04aafdb038dda0847dd988d\z
          cda6f3bfd15c4b4c4525004aa06eeff8\z
          ca61783aacec57fb3d1f92b0fe2fd1a8\z
          5f6724517b65e614ad6808d6f6ee34df\z
          f7310fdc82aebfd904b01e1dc54b2927\z
          094b2db68d6f903b68401adebf5a7e08\z
          d78ff4ef5d63653a65040cf9bfd4aca7\z
          984a74d37145986780fc0b16ac451649\z
          de6188a7dbdf191f64b5fc5e2ab47b57\z
          f7f7276cd419c17a3ca8e1b939ae49e4\z
          88acba6b965610b5480109c8b17b80e1\z
          b7b750dfc7598d5d5011fd2dcc5600a3\z
          2ef5b52a1ecc820e308aa342721aac09\z
          43bf6686b64b2579376504ccc493d97e\z
          6aed3fb0f9cd71a43dd497f01f17c0e2\z
          cb3797aa2a2f256656168e6c496afc5f\z
          b93246f6b1116398a346f1a641f3b041\z
          e989f7914f90cc2c7fff357876e506b5\z
          0d334ba77c225bc307ba537152f3f161\z
          0e4eafe595f6d9d90d11faa933a15ef1\z
          369546868a7f3a45a96768d40fd9d034\z
          12c091c6315cf4fde7cb68606937380d\z
          b2eaaa707b4c4185c32eddcdd306705e\z
          4dc1ffc872eeee475a64dfac86aba41c\z
          0618983f8741c5ef68d3a101e8a3b8ca\z
          c60c905c15fc910840b94c00a0b9d0"
        )
        local signature = util.fromHex(
          "0aab4c900501b3e24d7cdf4663326a3a\z
          87df5e4843b2cbdb67cbf6e460fec350\z
          aa5371b1508f9f4528ecea23c436d94b\z
          5e8fcd4f681e30a6ac00a9704a188a03"
        )

        assert.is.True(curve25519.verifyEd25519(publicKey, message, signature))
      end)

      test("Test vector SHA(abc)", function()
        local publicKey = util.fromHex(
          "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf"
        )
        local message = util.fromHex(
          "ddaf35a193617abacc417349ae204131\z
          12e6fa4e89a97ea20a9eeee64b55d39a\z
          2192992a274fc1a836ba3c23a3feebbd\z
          454d4423643ce80e2a9ac94fa54ca49f"
        )
        local signature = util.fromHex(
          "dc2a4459e7369633a52b1bf277839a00\z
          201009a3efbf3ecb69bea2186c26b589\z
          09351fc9ac90b3ecfdfbc7c66431e030\z
          3dca179c138ac17ad9bef1177331a704"
        )

        assert.is.True(curve25519.verifyEd25519(publicKey, message, signature))
      end)
    end)

    context("Project Wycheproof test vectors #wycheproof", function()
      testUtil.makeWycheproofTests {
        file = "eddsa_test.json",

        groupName = function(testGroup)
          return "EdDSA"
        end,

        runTest = function(testSpec, testGroup)
          local publicKey = util.fromHex(testGroup.key.pk)
          local message = util.fromHex(testSpec.msg)
          local signature = util.fromHex(testSpec.sig)

          if testSpec.result == "valid" then
            assert.is.True((
              curve25519.verifyEd25519(publicKey, message, signature)
            ))
          else
            assert.is.Nil((
              curve25519.verifyEd25519(publicKey, message, signature)
            ))
          end
        end,
      }
    end)
  end)

  context("Ed25519 digital signature generation #ed25519", function()
    context("RFC 8032 test vectors", function()
      test("Test vector 1", function()
        local privateKey = util.fromHex(
          "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
        )
        local message = ""
        local signature =
          "e5564300c360ac729086e2cc806e828a\z
          84877f1eb8e5d974d873e06522490155\z
          5fb8821590a33bacc61e39701cf9b46b\z
          d25bf5f0595bbe24655141438e7a100b"

        assert.are.equal(
          signature,
          util.toHex(curve25519.signEd25519(privateKey, message))
        )
      end)

      test("Test vector 2", function()
        local privateKey = util.fromHex(
          "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"
        )
        local message = util.fromHex("72")
        local signature =
          "92a009a9f0d4cab8720e820b5f642540\z
          a2b27b5416503f8fb3762223ebdb69da\z
          085ac1e43e15996e458f3613d0f11d8c\z
          387b2eaeb4302aeeb00d291612bb0c00"

        assert.are.equal(
          signature,
          util.toHex(curve25519.signEd25519(privateKey, message))
        )
      end)

      test("Test vector 3", function()
        local privateKey = util.fromHex(
          "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7"
        )
        local message = util.fromHex("af82")
        local signature =
          "6291d657deec24024827e69c3abe01a3\z
          0ce548a284743a445e3680d7db5ac3ac\z
          18ff9b538d16f290ae67f760984dc659\z
          4a7c15e9716ed28dc027beceea1ec40a"

        assert.are.equal(
          signature,
          util.toHex(curve25519.signEd25519(privateKey, message))
        )
      end)

      test("Test vector 1024", function()
        local privateKey = util.fromHex(
          "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
        )
        local message = util.fromHex(
          "08b8b2b733424243760fe426a4b54908\z
          632110a66c2f6591eabd3345e3e4eb98\z
          fa6e264bf09efe12ee50f8f54e9f77b1\z
          e355f6c50544e23fb1433ddf73be84d8\z
          79de7c0046dc4996d9e773f4bc9efe57\z
          38829adb26c81b37c93a1b270b20329d\z
          658675fc6ea534e0810a4432826bf58c\z
          941efb65d57a338bbd2e26640f89ffbc\z
          1a858efcb8550ee3a5e1998bd177e93a\z
          7363c344fe6b199ee5d02e82d522c4fe\z
          ba15452f80288a821a579116ec6dad2b\z
          3b310da903401aa62100ab5d1a36553e\z
          06203b33890cc9b832f79ef80560ccb9\z
          a39ce767967ed628c6ad573cb116dbef\z
          efd75499da96bd68a8a97b928a8bbc10\z
          3b6621fcde2beca1231d206be6cd9ec7\z
          aff6f6c94fcd7204ed3455c68c83f4a4\z
          1da4af2b74ef5c53f1d8ac70bdcb7ed1\z
          85ce81bd84359d44254d95629e9855a9\z
          4a7c1958d1f8ada5d0532ed8a5aa3fb2\z
          d17ba70eb6248e594e1a2297acbbb39d\z
          502f1a8c6eb6f1ce22b3de1a1f40cc24\z
          554119a831a9aad6079cad88425de6bd\z
          e1a9187ebb6092cf67bf2b13fd65f270\z
          88d78b7e883c8759d2c4f5c65adb7553\z
          878ad575f9fad878e80a0c9ba63bcbcc\z
          2732e69485bbc9c90bfbd62481d9089b\z
          eccf80cfe2df16a2cf65bd92dd597b07\z
          07e0917af48bbb75fed413d238f5555a\z
          7a569d80c3414a8d0859dc65a46128ba\z
          b27af87a71314f318c782b23ebfe808b\z
          82b0ce26401d2e22f04d83d1255dc51a\z
          ddd3b75a2b1ae0784504df543af8969b\z
          e3ea7082ff7fc9888c144da2af58429e\z
          c96031dbcad3dad9af0dcbaaaf268cb8\z
          fcffead94f3c7ca495e056a9b47acdb7\z
          51fb73e666c6c655ade8297297d07ad1\z
          ba5e43f1bca32301651339e22904cc8c\z
          42f58c30c04aafdb038dda0847dd988d\z
          cda6f3bfd15c4b4c4525004aa06eeff8\z
          ca61783aacec57fb3d1f92b0fe2fd1a8\z
          5f6724517b65e614ad6808d6f6ee34df\z
          f7310fdc82aebfd904b01e1dc54b2927\z
          094b2db68d6f903b68401adebf5a7e08\z
          d78ff4ef5d63653a65040cf9bfd4aca7\z
          984a74d37145986780fc0b16ac451649\z
          de6188a7dbdf191f64b5fc5e2ab47b57\z
          f7f7276cd419c17a3ca8e1b939ae49e4\z
          88acba6b965610b5480109c8b17b80e1\z
          b7b750dfc7598d5d5011fd2dcc5600a3\z
          2ef5b52a1ecc820e308aa342721aac09\z
          43bf6686b64b2579376504ccc493d97e\z
          6aed3fb0f9cd71a43dd497f01f17c0e2\z
          cb3797aa2a2f256656168e6c496afc5f\z
          b93246f6b1116398a346f1a641f3b041\z
          e989f7914f90cc2c7fff357876e506b5\z
          0d334ba77c225bc307ba537152f3f161\z
          0e4eafe595f6d9d90d11faa933a15ef1\z
          369546868a7f3a45a96768d40fd9d034\z
          12c091c6315cf4fde7cb68606937380d\z
          b2eaaa707b4c4185c32eddcdd306705e\z
          4dc1ffc872eeee475a64dfac86aba41c\z
          0618983f8741c5ef68d3a101e8a3b8ca\z
          c60c905c15fc910840b94c00a0b9d0"
        )
        local signature =
          "0aab4c900501b3e24d7cdf4663326a3a\z
          87df5e4843b2cbdb67cbf6e460fec350\z
          aa5371b1508f9f4528ecea23c436d94b\z
          5e8fcd4f681e30a6ac00a9704a188a03"

        assert.are.equal(
          signature,
          util.toHex(curve25519.signEd25519(privateKey, message))
        )
      end)

      test("Test vector SHA(abc)", function()
        local privateKey = util.fromHex(
          "833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42"
        )
        local message = util.fromHex(
          "ddaf35a193617abacc417349ae204131\z
          12e6fa4e89a97ea20a9eeee64b55d39a\z
          2192992a274fc1a836ba3c23a3feebbd\z
          454d4423643ce80e2a9ac94fa54ca49f"
        )
        local signature =
          "dc2a4459e7369633a52b1bf277839a00\z
          201009a3efbf3ecb69bea2186c26b589\z
          09351fc9ac90b3ecfdfbc7c66431e030\z
          3dca179c138ac17ad9bef1177331a704"

        assert.are.equal(
          signature,
          util.toHex(curve25519.signEd25519(privateKey, message))
        )
      end)
    end)

    context("Project Wycheproof test vectors #wycheproof", function()
      testUtil.makeWycheproofTests {
        file = "eddsa_test.json",

        groupName = function(testGroup)
          return "EdDSA"
        end,

        testFilter = function(testSpec)
          return testSpec.result == "valid"
        end,

        runTest = function(testSpec, testGroup)
          local privateKey = util.fromHex(testGroup.key.sk)
          local message = util.fromHex(testSpec.msg)
          local signature = util.fromHex(testSpec.sig)

          assert.are.equal(
            util.toHex(signature),
            util.toHex(curve25519.signEd25519(privateKey, message))
          )
        end,
      }
    end)
  end)

  test("Ed25519 keypair creation #ed25519", function()
    local keygen = curve25519.makeEd25519KeyGen(function(n)
      return ("\xa5"):rep(n)
    end)
    local keypair = keygen()

    assert.are.equal(
      util.toHex(keypair.public),
      util.toHex(curve25519.ed25519PublicKeyFromPrivate(keypair.private))
    )

    local message = "hello, world!"
    local signature = curve25519.signEd25519(keypair.private, message)

    assert.is.True(curve25519.verifyEd25519(keypair.public, message, signature))
  end)
end)

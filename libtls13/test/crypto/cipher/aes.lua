local util = require("tls13.util")

context("AES tests #crypto #cipher #aes", function()
  local aes = require("tls13.crypto.cipher.aes")

  context("AES-128 tests #aes128", function()
    local aes128 = aes.aes128

    test("encrypt then decrypt", function()
      local plaintext = "\0\1\2\3\4\5\6\7\8\9\x0a\x0b\x0c\x0d\x0e\x0f"
      local key = "fedcba9876543210"
      assert.are.equal(
        util.toHex(plaintext),
        util.toHex(aes128:decrypt(aes128:encrypt(plaintext, key), key))
      )
    end)

    test("NIST example vectors", function()
      local blocks = {
        util.fromHex("6bc1bee22e409f96e93d7e117393172a"),
        util.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
        util.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
        util.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
      }
      local key = util.fromHex("2b7e151628aed2a6abf7158809cf4f3c")

      assert.are.equal(
        "3ad77bb40d7a3660a89ecaf32466ef97",
        util.toHex(aes128:encrypt(blocks[1], key))
      )
      assert.are.equal(
        "f5d3d58503b9699de785895a96fdbaaf",
        util.toHex(aes128:encrypt(blocks[2], key))
      )
      assert.are.equal(
        "43b1cd7f598ece23881b00e3ed030688",
        util.toHex(aes128:encrypt(blocks[3], key))
      )
      assert.are.equal(
        "7b0c785e27e8ad3f8223207104725dd4",
        util.toHex(aes128:encrypt(blocks[4], key))
      )
    end)
  end)

  context("AES-256 tests #aes256", function()
    local aes256 = aes.aes256

    test("encrypt then decrypt", function()
      local plaintext = "\0\1\2\3\4\5\6\7\8\9\x0a\x0b\x0c\x0d\x0e\x0f"
      local key = "fedcba9876543210fedcba9876543210"
      assert.are.equal(
        util.toHex(plaintext),
        util.toHex(aes256:decrypt(aes256:encrypt(plaintext, key), key))
      )
    end)

    test("NIST example vectors", function()
      local blocks = {
        util.fromHex("6bc1bee22e409f96e93d7e117393172a"),
        util.fromHex("ae2d8a571e03ac9c9eb76fac45af8e51"),
        util.fromHex("30c81c46a35ce411e5fbc1191a0a52ef"),
        util.fromHex("f69f2445df4f9b17ad2b417be66c3710"),
      }
      local key = util.fromHex(
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"
      )

      assert.are.equal(
        "f3eed1bdb5d2a03c064b5a7e3db181f8",
        util.toHex(aes256:encrypt(blocks[1], key))
      )
      assert.are.equal(
        "591ccb10d410ed26dc5ba74a31362870",
        util.toHex(aes256:encrypt(blocks[2], key))
      )
      assert.are.equal(
        "b6ed21b99ca6f4f9f153e7b1beafed1d",
        util.toHex(aes256:encrypt(blocks[3], key))
      )
      assert.are.equal(
        "23304b7a39f9f3ff067d8d8f9e24ecc7",
        util.toHex(aes256:encrypt(blocks[4], key))
      )
    end)
  end)
end)

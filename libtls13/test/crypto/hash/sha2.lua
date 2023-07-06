local util = require("tls13.util")

context("SHA2-256 tests #crypto #hash #sha2 #sha2-256", function()
  local sha2 = require("tls13.crypto.hash.sha2")

  local function hash(message)
    local bytes = sha2.sha256()
      :update(message)
      :finish()

    return util.toHex(bytes)
  end

  test("zero-length message", function()
    assert.are.equal(
      "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
      hash("")
    )
  end)

  test("hello world", function()
    assert.are.equal(
      "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
      hash("hello world")
    )
  end)

  context("messages from data/sha256.txt", function()
    for line in io.lines("./test/data/sha256.txt") do
      local inputHex, expectedHash = line:match("(%S+) (%S+)")
      local input = util.fromHex(inputHex)

      test(#input .. "-byte input", function()
        assert.are.equal(expectedHash, hash(input))
      end)
    end
  end)

  test("chunked", function()
    local hasher = sha2.sha256()
    hasher:update(("\1"):rep(30))
    hasher:update(("\2"):rep(41))
    hasher:update("")
    hasher:update(("\3"):rep(500))

    assert.are.equal(
      hash(("\1"):rep(30) .. ("\2"):rep(41) .. ("\3"):rep(500)),
      util.toHex(hasher:finish())
    )
  end)
end)

context("SHA2-384 tests #crypto #hash #sha2 #sha2-384", function()
  local sha2 = require("tls13.crypto.hash.sha2")

  local function hash(message)
    local bytes = sha2.sha384()
      :update(message)
      :finish()

    return util.toHex(bytes)
  end

  test("zero-length message", function()
    assert.are.equal(
      "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b",
      hash("")
    )
  end)

  test("hello world", function()
    assert.are.equal(
      "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e417cb71ce646efd0819dd8c088de1bd",
      hash("hello world")
    )
  end)

  context("messages from data/sha384.txt", function()
    for line in io.lines("./test/data/sha384.txt") do
      local inputHex, expectedHash = line:match("(%S+) (%S+)")
      local input = util.fromHex(inputHex)

      test(#input .. "-byte input", function()
        assert.are.equal(expectedHash, hash(input))
      end)
    end
  end)

  test("chunked", function()
    local hasher = sha2.sha384()
    hasher:update(("\1"):rep(30))
    hasher:update(("\2"):rep(41))
    hasher:update("")
    hasher:update(("\3"):rep(500))

    assert.are.equal(
      hash(("\1"):rep(30) .. ("\2"):rep(41) .. ("\3"):rep(500)),
      util.toHex(hasher:finish())
    )
  end)
end)

context("SHA2-512 tests #crypto #hash #sha2 #sha2-512", function()
  local sha2 = require("tls13.crypto.hash.sha2")

  local function hash(message)
    local bytes = sha2.sha512()
      :update(message)
      :finish()

    return util.toHex(bytes)
  end

  test("zero-length message", function()
    assert.are.equal(
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e",
      hash("")
    )
  end)

  test("hello world", function()
    assert.are.equal(
      "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f",
      hash("hello world")
    )
  end)

  context("messages from data/sha512.txt", function()
    for line in io.lines("./test/data/sha512.txt") do
      local inputHex, expectedHash = line:match("(%S+) (%S+)")
      local input = util.fromHex(inputHex)

      test(#input .. "-byte input", function()
        assert.are.equal(expectedHash, hash(input))
      end)
    end
  end)

  test("chunked", function()
    local hasher = sha2.sha512()
    hasher:update(("\1"):rep(30))
    hasher:update(("\2"):rep(41))
    hasher:update("")
    hasher:update(("\3"):rep(500))

    assert.are.equal(
      hash(("\1"):rep(30) .. ("\2"):rep(41) .. ("\3"):rep(500)),
      util.toHex(hasher:finish())
    )
  end)
end)

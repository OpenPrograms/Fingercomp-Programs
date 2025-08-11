local match = require("luassert.match")

local util = require("tls13.util")

context("ASN.1 DER decoder tests #asn #der", function()
  local asn = require("tls13.asn")

  test("OCTET STRING", function()
    local s = "hello, world!"
    local encoded = "\x04" .. string.char(#s) .. s
    local decode = spy.new(asn.decode)
    local result = decode(encoded)

    assert.spy(decode).returned.with(match.is.table())
    assert.same(s, result[1])
    assert.same(asn.asnTags.universal.octetString, result.TAG)
    assert.same("primitive", result.ENCODING)
    assert.same(#s, result.LENGTH)
    assert.same(1, result.START)
    assert.same(#encoded, result.END)
  end)

  test("SEQUENCE of OCTET STRINGs", function()
    local s1 = "hello"
    local s2 = "world"
    local encodedS1 = "\x04" .. string.char(#s1) .. s1
    local encodedS2 = "\x04" .. string.char(#s2) .. s2
    local innerLength = #encodedS1 + #encodedS2
    local encoded = "\x30"
      .. string.char(innerLength)
      .. encodedS1
      .. encodedS2

    local decode = spy.new(asn.decode)
    local result = decode(encoded)
    assert.spy(decode).returned.with(match.is.table())

    assert.same(asn.asnTags.universal.sequence, result.TAG)
    assert.same("constructed", result.ENCODING)
    assert.same(innerLength, result.LENGTH)
    assert.same(1, result.START)
    assert.same(#encoded, result.END)

    local v1 = result[1]
    assert.same(asn.asnTags.universal.octetString, v1.TAG)
    assert.same("primitive", v1.ENCODING)
    assert.same(#s1, v1.LENGTH)
    assert.same(3, v1.START)
    assert.same(3 + #encodedS1 - 1, v1.END)
    assert.same(s1, v1[1])
    assert.same(
      util.toHex(encodedS1),
      util.toHex(encoded:sub(v1.START, v1.END))
    )

    local v2 = result[2]
    assert.same(asn.asnTags.universal.octetString, v2.TAG)
    assert.same("primitive", v2.ENCODING)
    assert.same(#s2, v2.LENGTH)
    assert.same(3 + #encodedS1, v2.START)
    assert.same(#encoded, v2.END)
    assert.same(s2, v2[1])
    assert.same(
      util.toHex(encodedS2),
      util.toHex(encoded:sub(v2.START, v2.END))
    )
  end)
end)

-- Recognized X.5xx attributes.

local asn = require("tls13.asn")
local oid = require("tls13.asn.oid")
local utilMap = require("tls13.util.map")

local lib = {}

lib.recognizedAttributes = utilMap.makeProjectionMap(tostring)

function lib.makeDirectoryStringAttribute(name)
  return {
    getName = function()
      return name
    end,

    parse = function(_, parser, value)
      return parser:parseDirectoryString(value)
    end,
  }
end

local makeDsAttr = lib.makeDirectoryStringAttribute

lib.recognizedAttributes[oid.at.commonName] = makeDsAttr("common name")
lib.recognizedAttributes[oid.at.surname] = makeDsAttr("surname")
lib.recognizedAttributes[oid.at.serialNumber] = makeDsAttr("serial number")
lib.recognizedAttributes[oid.at.countryName] = makeDsAttr("country")
lib.recognizedAttributes[oid.at.localityName] = makeDsAttr("locality")
lib.recognizedAttributes[oid.at.stateOrProvinceName] =
  makeDsAttr("state or province")
lib.recognizedAttributes[oid.at.organizationName] = makeDsAttr("organization")
lib.recognizedAttributes[oid.at.organizationalUnitName] =
  makeDsAttr("organizational unit")
lib.recognizedAttributes[oid.at.title] = makeDsAttr("title")
lib.recognizedAttributes[oid.at.name] = makeDsAttr("name")
lib.recognizedAttributes[oid.at.givenName] = makeDsAttr("given name")
lib.recognizedAttributes[oid.at.initials] = makeDsAttr("initials")
lib.recognizedAttributes[oid.at.generationQualifier] =
  makeDsAttr("generation qualifier")
lib.recognizedAttributes[oid.at.dnQualifier] =
  makeDsAttr("distinguished name qualifier")
lib.recognizedAttributes[oid.at.pseudonym] = makeDsAttr("pseudonym")

lib.recognizedAttributes[oid.domainComponent] = {
  getName = function()
    return "domain component"
  end,

  parse = function(self, parser, value)
    local value, err = parser:checkTag(value, asn.asnTags.universal.ia5String)

    if not value then
      return nil, err
    end

    return value[1]
  end,
}

return lib

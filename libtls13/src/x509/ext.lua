-- Recognized X.509 certificate extensions.

local asn = require("tls13.asn")
local errors = require("tls13.error")
local oid = require("tls13.asn.oid")
local util = require("tls13.util")
local utilMap = require("tls13.util.map")

local lib = {}

-- Values are expected to have two fields: `getName` and `parse`.
-- In addition, `nonDerEncodedValue` may be set to a truthy value to avoid
-- decoding the contents of extnValue with DER before parsing.
lib.recognizedExtensions = utilMap.makeProjectionMap(tostring)

local function makeExtension(name, parser)
  return {
    getName = function()
      return name
    end,

    parse = parser,
  }
end

lib.recognizedExtensions[oid.ce.keyUsage] = makeExtension(
  "keyUsage",
  function(_, parser, value)
    local bits, err = parser:checkTag(value, asn.asnTags.universal.bitString)

    if not bits then
      return nil, err
    end

    local purposes = {
      digitalSignature = bits[1][0] or false,
      nonRepudiation = bits[1][1] or false,
      keyEncipherment = bits[1][2] or false,
      dataEncipherment = bits[1][3] or false,
      keyAgreement = bits[1][4] or false,
      keyCertSign = bits[1][5] or false,
      cRLSign = bits[1][6] or false,
      encipherOnly = bits[1][7] or false,
      decipherOnly = bits[1][8] or false,
    }

    for _, bit in pairs(purposes) do
      if bit then
        return purposes
      end
    end

    -- all bits are zero
    return nil, parser:makeError(errors.x509.keyUsageAllZero)
  end
)

local certificatePolicies = {
  recognizedPolicies = utilMap.makeProjectionMap(tostring),
  recognizedQualifiers = utilMap.makeProjectionMap(tostring),

  getName = function()
    return "certificatePolicies"
  end,

  parse = function(self, parser, value)
    local policySeq, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not policySeq then
      return nil, err
    end

    if #policySeq == 0 then
      return nil, parser:makeError(errors.x509.certificatePoliciesEmpty)
    end

    local policies = utilMap.makeProjectionMap(tostring)

    for i, policy in ipairs(value) do
      local policy, err = parser:withPath("#" .. i, function()
        local policy, err = self:parsePolicyInformation(parser, policy)

        if not policy then
          return nil, err
        elseif policies[policy.policyIdentifier] then
          return nil, parser:makeError(errors.x509.duplicateCertificatePolicy)
        else
          return policy
        end
      end)

      if not policy then
        return nil, err
      end

      policies[policy.policyIdentifier] = policy
    end

    return policies
  end,

  parsePolicyInformation = function(self, parser, policy)
    local result, err = {}
    policy, err = parser:checkTag(policy, asn.asnTags.universal.sequence)

    if not policy then
      return nil, err
    end

    result.policyIdentifier, err =
      parser:withField(policy, 1, "policyIdentifier", parser.parseOid)

    if not result.policyIdentifier then
      return nil, err
    end

    local recognizedPolicy = self.recognizedPolicies[result.policyIdentifier]
    parser:renamePathLabel(("%s: %s"):format(
      parser:getPath(),
      recognizedPolicy and recognizedPolicy:getName() or result.policyIdentifier
    ))

    if policy[2] then
      result.policyQualifiers, err = parser:withField(
        policy,
        2,
        "policyQualifiers",
        function(_, quals)
          return self:parsePolicyQualifiers(parser, quals)
        end
      )

      if not result.policyQualifiers then
        return nil, err
      end
    end

    if recognizedPolicy then
      local parseResult, err = recognizedPolicy:parse(parser, result)

      if not parseResult then
        return nil, err
      end
    end

    return result
  end,

  parsePolicyQualifiers = function(self, parser, quals)
    local result, err = {}
    quals, err = parser:checkTag(quals, asn.asnTags.universal.sequence)

    if not quals then
      return nil, err
    end

    if #quals == 0 then
      return nil, parser:makeError(errors.x509.sequenceEmpty)
    end

    for i, qual in ipairs(quals) do
      result[i], err = parser:withPath("#" .. i, function()
        return self:parsePolicyQualifierInfo(parser, qual)
      end)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end,

  parsePolicyQualifierInfo = function(self, parser, qual)
    local result, err = {}
    qual, err = parser:checkTag(qual, asn.asnTags.universal.sequence)

    if not qual then
      return nil, err
    end

    result.policyQualifierId, err =
      parser:withField(qual, 1, "policyQualifierId", parser.parseOid)

    if not result.policyQualifierId then
      return nil, err
    end

    local recognizedQualifier =
      self.recognizedQualifiers[result.policyQualifierId]
    parser:renamePathLabel(("%s: %s"):format(
      parser:getPath(),
      recognizedQualifier and recognizedQualifier:getName()
        or result.policyQualifierId
    ))

    result.qualifier, err =
      parser:withField(qual, 2, "qualifier", function(_, qual)
        if recognizedQualifier then
          return recognizedQualifier:parse(parser, qual)
        else
          return qual
        end
      end)

    if result.qualifier == nil then
      return nil, err
    end

    return result
  end,
}

certificatePolicies.recognizedQualifiers[oid.pkix.qt.cps] = {
  getName = function()
    return "certification practice statement"
  end,

  parse = function(self, parser, qual)
    return parser:parseIa5String(qual)
  end,
}

certificatePolicies.recognizedQualifiers[oid.pkix.qt.unotice] = {
  getName = function()
    return "user notice"
  end,

  parse = function(self, parser, qual)
    local fieldIdx = util.makeCounter()
    local userNotice, err =
      parser:checkTag(qual, asn.asnTags.universal.sequence)

    if not userNotice then
      return nil, err
    end

    local result = {}

    if #userNotice == 0 then
      return result
    end

    if userNotice[#fieldIdx]
        and userNotice[#fieldIdx] == asn.asnTags.universal.sequence then
      result.noticeRef, err = parser:withField(
        userNotice,
        fieldIdx:next(),
        "noticeRef",
        function(_, ref)
          return self:parseNoticeReference(parser, ref)
        end
      )

      if not result.noticeRef then
        return nil, err
      end
    end

    if userNotice[#fieldIdx] then
      result.explicitText = parser:withField(
        userNotice,
        fieldIdx:next(),
        "explicitText",
        function(_, ref)
          return self:parseDisplayText(parser, ref)
        end
      )

      if not result.explicitText then
        return nil, err
      end
    end

    return result
  end,

  parseNoticeReference = function(self, parser, ref)
    local result, err = {}
    ref, err = parser:checkTag(ref, asn.asnTags.universal.sequence)

    if not ref then
      return nil, err
    end

    result.organization, err = parser:withField(
      ref,
      1,
      "organization",
      function(_, org)
        return self:parseDisplayText(parser, org)
      end
    )

    if not result.organization then
      return nil, err
    end

    result.noticeNumbers, err = parser:withField(
      ref,
      2,
      "noticeNumbers",
      function(_, nums)
        return self:parseNoticeNumbers(parser, nums)
      end
    )

    if not result.noticeNumbers then
      return nil, err
    end

    return result
  end,

  parseNoticeNumbers = function(self, parser, nums)
    local result, err = {}
    nums, err = parser:checkTag(nums, asn.asnTags.universal.sequence)

    if not nums then
      return nil, err
    end

    for i, num in ipairs(nums) do
      result[i], err = parser:withPath("#" .. i, function()
        return self:parseNoticeNumber(parser, num)
      end)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end,

  parseNoticeNumber = function(self, parser, num)
    local num, err = parser:checkTag(num, asn.asnTags.universal.integer)

    if not num then
      return nil, err
    end

    return num[1]
  end,

  parseDisplayText = function(self, parser, text)
    if text.TAG == asn.asnTags.universal.ia5String then
      return parser:parseIa5String(text)
    elseif text.TAG == asn.asnTags.universal.visibleString then
      return parser:parseVisibleString(text)
    elseif text.TAG == asn.asnTags.universal.bmpString then
      return parser:parseBmpString(text)
    elseif text.TAG == asn.asnTags.universal.utf8String then
      return parser:parseUtf8String(text)
    else
      return nil, parser:makeError(
        errors.x509.invalidType,
        text.TAG, "DisplayText"
      )
    end
  end,
}

certificatePolicies.recognizedPolicies[oid.ce.certificatePolicies.anyPolicy] = {
  getName = function()
    return "any policy"
  end,

  parse = function(self, parser, policy)
    return true
  end,
}

lib.recognizedExtensions[oid.ce.certificatePolicies] = certificatePolicies

lib.recognizedExtensions[oid.ce.policyMappings] = {
  getName = function()
    return "policyMappings"
  end,

  parse = function(self, parser, value)
    local result = {}
    local mappings, err = parser:checkTag(value, asn.asnTag.universal.sequence)

    if not mappings then
      return nil, err
    end

    for i, mapping in ipairs(mappings) do
      result[i], err = parser:withPath("#" .. i, function()
        return self:parseMapping(parser, mapping)
      end)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end,

  parseMapping = function(self, parser, mapping)
    local result, err = {}
    mapping, err = parser:checkTag(mapping, asn.asnTags.universal.sequence)

    if not mapping then
      return nil, err
    end

    result.issuerDomainPolicy, err = parser:withField(
      mapping,
      1,
      "issuerDomainPolicy",
      function(_, id)
        return self:parseCertPolicyId(parser, id)
      end
    )

    if not result.issuerDomainPolicy then
      return nil, err
    end

    result.subjectDomainPolicy, err = parser:withField(
      mapping,
      2,
      "subjectDomainPolicy",
      function(_, id)
        return self:parseCertPolicyId(parser, id)
      end
    )

    if not result.subjectDomainPolicy then
      return nil, err
    end

    return result
  end,

  parseCertPolicyId = function(self, parser, id)
    local id, err = parser:parseOid(id)

    if not id then
      return nil, err
    end

    if id == oid.ce.certificatePolicies.anyPolicy then
      return nil, parser:makeError(errors.x509.policyMappingAnyPolicy)
    end

    return id
  end,
}

local function andThen(f, result, err)
  if not result then
    return nil, err
  end

  return f(result)
end

local function andThenAssignToKey(key, result, err)
  if not result then
    return nil, err
  end

  return {[key] = result}
end

local function parseOtherName(parser, name)
  local result, err = {}
  name, err = parser:checktag(name, asn.asnTags.universal.sequence)

  if not name then
    return nil, err
  end

  result.typeId, err = parser:withField(name, 1, "type-id", parser.parseOid)

  if not result.typeId then
    return nil, err
  end

  result.value, err = parser:withField(name, 2, "value", function(parser, value)
    return parser:checkExplicitTag(value, asn.makeTagSpec("contextSpecific", 0))
  end)

  if not result.value then
    return nil, err
  end

  return result
end

local function parseEdiPartyName(parser, name)
  local fieldIdx = util.makeCounter()
  local result, err = {}
  name, err = parser:checkTag(name, asn.asnTags.universal.sequence)

  if not name then
    return nil, err
  end

  local function parseExplicitDirectoryString(tagNumber)
    return function(parser, name)
      local name, err = parser:checkExplicitTag(
        name,
        asn.makeTagSpec("contextSpecific", tagNumber)
      )

      if not name then
        return nil, err
      end

      return parser:parseDirectoryString(name)
    end
  end

  if name[#fieldIdx] and
      name[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 0) then
    result.nameAssigner, err = parser:withField(
      name,
      fieldIdx:next(),
      "nameAssigner",
      parseExplicitDirectoryString(0)
    )

    if not result.nameAssigner then
      return nil, err
    end
  end

  result.partyName, err = parser:withField(
    name,
    fieldIdx:next(),
    "partyName",
    parseExplicitDirectoryString(1)
  )

  if not result.partyName then
    return nil, err
  end

  return result
end

local function parseIpAddress(parser, addr)
  local addr, err = parser:checkTag(addr, asn.asnTags.universal.octetString)

  if not addr then
    return nil, err
  end

  if #addr[1] == 4 then
    -- IPv4 address
    local result = {(">BBBB"):unpack(addr[1])}
    return table.concat(result, ".", 1, 4)
  elseif #addr[1] == 16 then
    -- IPv6 address
    local result = {}

    for part in addr[1]:gmatch("..") do
      table.insert(result, ("%x"):format((">I2"):unpack(part)))
    end

    return "[" .. table.concat(result, ":") .. "]"
  else
    return nil, parser:makeError(errors.x509.malformedIpAddress, #addr[1])
  end
end

local function parseGeneralName(parser, name)
  if name.TAG == asn.makeTagSpec("contextSpecific", 0) then
    return andThenAssignToKey("otherName", andThen(
      function(name) return parseOtherName(parser, name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.sequence)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 1) then
    return andThenAssignToKey("rfc822Name", andThen(
      function(name) return parser:parseIa5String(name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.ia5String)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 2) then
    return andThenAssignToKey("dNSName", andThen(
      function(name) return parser:parseIa5String(name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.ia5String)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 3) then
    return andThenAssignToKey(
      "x400Address",
        -- you parse that yourself k?
      parser:checkImplicitTag(name, asn.asnTags.universal.sequence)
    )
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 4) then
    return andThenAssignToKey("directoryName", andThen(
      function(name) return parser:parseDirectoryString(name) end,
      parser:checkExplicitTag(name)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 5) then
    return andThenAssignToKey("ediPartyName", andThen(
      function(name) return parseEdiPartyName(parser, name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.sequence)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 6) then
    return andThenAssignToKey(
      -- like, they just *had* to spell this one out, uhhh
      "uniformResourceIdentifier",
      andThen(
        function(name) return parser:parseIa5String(name) end,
        parser:checkImplicitTag(name, asn.asnTags.universal.ia5String)
      )
    )
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 7) then
    return andThenAssignToKey("iPAddress", andThen(
      function(name) return parseIpAddress(parser, name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.octetString)
    ))
  elseif name.TAG == asn.makeTagSpec("contextSpecific", 8) then
    return andThenAssignToKey("registeredID", andThen(
      function(name) return parser:parseOid(name) end,
      parser:checkImplicitTag(name, asn.asnTags.universal.objectIdentifier)
    ))
  else
    return nil, parser:makeError(
      errors.x509.invalidType,
      name.TAG, "GeneralName"
    )
  end
end

local function parseGeneralNames(parser, names)
  local result, err = {}
  names, err = parser:checkTag(names, asn.asnTags.universal.sequence)

  if not names then
    return nil, err
  end

  if #names == 0 then
    return nil, parser:makeError(errors.x509.sequenceEmpty)
  end

  for i, name in ipairs(names) do
    result[i], err = parser:withPath("#" .. i, function()
      return parseGeneralName(parser, name)
    end)

    if not result[i] then
      return nil, err
    end
  end

  return result
end

local function parseAltName(_, parser, value)
  return parseGeneralNames(parser, value)
end

lib.recognizedExtensions[oid.ce.subjectAltName] =
  makeExtension("subjectAltName", parseAltName)
lib.recognizedExtensions[oid.ce.issuerAltName] =
  makeExtension("issuerAltName", parseAltName)

lib.recognizedExtensions[oid.ce.basicConstraints] =
  makeExtension("basicConstraints", function(_, parser, value)
    local fieldIdx = util.makeCounter()
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    result.cA = false

    if value[#fieldIdx]
        and value[#fieldIdx].TAG == asn.asnTags.universal.boolean then
      result.cA, err =
        parser:withField(value, fieldIdx:next(), "cA", function(_, ca)
          return ca[1]
        end)

      if result.cA == nil then
        return nil, err
      end
    end

    if value[#fieldIdx] then
      result.pathLenConstraint, err = parser:withField(
        value,
        fieldIdx:next(),
        "pathLenConstraint",
        function(parser, len)
          local len, err = parser:checkTag(len, asn.asnTags.universal.integer)

          if not len then
            return nil, err
          end

          if len.long then
            return nil, parser:makeError(errors.x509.valueTooLarge)
          end

          if len[1] < 0 then
            return nil, parser:makeError(errors.x509.negativeForbidden)
          end

          return len[1]
        end
      )

      if not result.pathLenConstraint then
        return nil, err
      end
    end

    return result
  end)

lib.recognizedExtensions[oid.ce.nameConstraints] = {
  getName = function()
    return "nameConstraints"
  end,

  parse = function(self, parser, value)
    local fieldIdx = util.makeCounter()
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    if value[#fieldIdx] and value[#fieldIdx].TAG
        == asn.makeTagSpec("contextSpecific", 0) then
      result.permittedSubtrees, err = parser:withField(
        value,
        fieldIdx:next(),
        "permittedSubtrees",
        function(parser, subtrees)
          return self:parseGeneralSubtrees(parser, subtrees, 0)
        end
      )

      if not result.permittedSubtrees then
        return nil, err
      end
    end

    if value[#fieldIdx] then
      result.excludedSubtrees, err = parser:withField(
        value,
        fieldIdx:next(),
        "excludedSubtrees",
        function(parser, subtrees)
          return self:parseGeneralSubtrees(parser, subtrees, 1)
        end
      )

      if not result.excludedSubtrees then
        return nil, err
      end
    end

    return result
  end,

  parseGeneralSubtrees = function(self, parser, subtrees, tagNumber)
    local result, err = {}
    subtrees, err = parser:checkImplicitTag(
      subtrees,
      asn.asnTags.universal.sequence,
      asn.makeTagSpec("contextSpecific", tagNumber)
    )

    if not subtrees then
      return nil, err
    end

    if #subtrees == 0 then
      return nil, parser:makeError(errors.x509.sequenceEmpty)
    end

    for i, subtree in ipairs(subtrees) do
      result[i], err = parser:withPath("#" .. i, function()
        return self:parseGeneralSubtree(parser, subtree)
      end)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end,

  parseGeneralSubtree = function(self, parser, subtree)
    local fieldIdx = util.makeCounter()
    local result, err = {}
    subtree, err = parser:checkTag(subtree, asn.asnTags.universal.sequence)

    if not subtree then
      return nil, err
    end

    result.base, err =
      parser:withField(subtree, fieldIdx:next(), "base", parseGeneralName)

    if not result.base then
      return nil, err
    end

    result.minimum = 0

    if subtree[#fieldIdx] and subtree[#fieldIdx]
        == asn.makeTagSpec("contextSpecific", 0) then
      result.minimum, err = parser:withField(
        subtree,
        fieldIdx:next(),
        "minimum",
        function(parser, min)
          return self:parseBaseDistance(parser, min, 0)
        end
      )

      if not result.minimum then
        return nil, err
      end
    end

    if subtree[#fieldIdx] then
      result.maximum, err = parser:withField(
        subtree,
        fieldIdx:next(),
        "maximum",
        function(parser, max)
          return self:parseBaseDistance(parser, max, 1)
        end
      )

      if not result.maximum then
        return nil, err
      end
    end

    return result
  end,

  parseBaseDistance = function(self, parser, dist, tagNumber)
    local dist, err = parser:checkImplicitTag(
      dist,
      asn.asnTags.universal.integer,
      asn.makeTagSpec("contextSpecific", tagNumber)
    )

    if not dist then
      return nil, err
    end

    if dist.long then
      return nil, parser:makeError(errors.x509.valueTooLarge)
    end

    if dist[1] < 0 then
      return nil, parser:makeError(errors.x509.negativeForbidden)
    end

    return dist[1]
  end,
}

local function parseSkipCerts(parser, skipCerts)
  local skipCerts, err =
    parser:checkTag(skipCerts, asn.asnTags.universal.integer)

  if not skipCerts then
    return nil, err
  end

  if skipCerts.long then
    return nil, parser:makeError(errors.x509.valueTooLarge)
  end

  if skipCerts[1] < 0 then
    return nil, parser:makeError(errors.x509.negativeForbidden)
  end

  return skipCerts[1]
end

lib.recognizedExtensions[oid.ce.policyConstraints] = {
  getName = function()
    return "policyConstraints"
  end,

  parse = function(self, parser, value)
    local fieldIdx = util.makeCounter()
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    if value[#fieldIdx] and value[#fieldIdx].TAG
        == asn.makeTagSpec("contextSpecific", 0) then
      result.requireExplicitPolicy, err = parser:withField(
        value,
        fieldIdx:next(),
        "requireExplicitPolicy",
        function(parser, skipCerts)
          return self:parseSkipCerts(parser, skipCerts, 0)
        end
      )

      if not result.requireExplicitPolicy then
        return nil, err
      end
    end

    if value[#fieldIdx] then
      result.inhibitPolicyMapping, err = parser:withField(
        value,
        fieldIdx:next(),
        "inhibitPolicyMapping",
        function(parser, skipCerts)
          return self:parserSkipCerts(parser, skipCerts, 1)
        end
      )

      if not result.inhibitPolicyMapping then
        return nil, err
      end
    end

    return result
  end,

  parseSkipCerts = function(self, parser, skipCerts, tagNumber)
    local skipCerts, err = parser:checkImplicitTag(
      skipCerts,
      asn.asnTags.universal.integer,
      asn.makeTagSpec("contextSpecific", tagNumber)
    )

    if not skipCerts then
      return nil, err
    end

    return parseSkipCerts(parser, skipCerts)
  end,
}

lib.recognizedExtensions[oid.ce.extKeyUsage] =
  makeExtension("extKeyUsage", function(self, parser, value)
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    for i, purpose in ipairs(value) do
      result[i], err = parser:withPath("#" .. i, parser.parseOid, purpose)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end)

lib.recognizedExtensions[oid.ce.cRLDistributionPoints] = {
  getName = function()
    return "cRLDistributionPoints"
  end,

  parse = function(self, parser, value)
    local result, err = {}
    value, err = parser:checkTag(value, asn.asnTags.universal.sequence)

    if not value then
      return nil, err
    end

    if #value == 0 then
      return nil, parser:makeError(errors.x509.sequenceEmpty)
    end

    for i, dp in ipairs(value) do
      result[i], err = parser:withPath("#" .. i, function()
        return self:parseDistributionPoint(parser, dp)
      end)

      if not result[i] then
        return nil, err
      end
    end

    return result
  end,

  parseDistributionPoint = function(self, parser, dp)
    local fieldIdx = util.makeCounter()
    local result, err = {}
    dp, err = parser:checkTag(dp, asn.asnTags.universal.sequence)

    if not dp then
      return nil, err
    end

    if dp[#fieldIdx]
        and dp[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 0) then
      result.distributionPoint, err = parser:withField(
        dp,
        fieldIdx:next(),
        "distributionPoint",
        function(parser, dpName)
          return self:parseDistributionPointName(parser, dpName)
        end
      )

      if not result.distributionPoint then
        return nil, err
      end
    end

    if dp[#fieldIdx]
        and dp[#fieldIdx].TAG == asn.makeTagSpec("contextSpecific", 1) then
      result.reasons, err = parser:withField(
        dp,
        fieldIdx:next(),
        "reasons",
        function(parser, reasons)
          return self:parseReasons(parser, reasons)
        end
      )

      if not result.reasons then
        return nil, err
      end
    end

    if dp[#fieldIdx] then
      result.cRLIssuer, err = parser:withField(
        dp,
        fieldIdx:next(),
        "cRLIssuer",
        function(parser, crlIssuer)
          return self:parseCrlIssuer(parser, crlIssuer)
        end
      )

      if not result.cRLIssuer then
        return nil, err
      end
    end

    if not result.cRLIssuer and not result.distributionPoint then
      return nil, parser:makeError(errors.x509.distributionPointUnspecified)
    end

    return result
  end,

  parseDistributionPointName = function(self, parser, dpName)
    local dpName, err = parser:checkExplicitTag(
      dpName,
      asn.makeTagSpec("contextSpecific", 0)
    )

    if not dpName then
      return nil, err
    end

    if dpName.TAG == asn.makeTagSpec("contextSpecific", 0) then
      local fullName, err = parser:checkImplicitTag(
        dpName,
        asn.asnTags.universal.sequence
      )

      if not fullName then
        return nil, err
      end

      return andThenAssignToKey("fullName", parseGeneralNames(parser, fullName))
    elseif dpName.TAG == asn.makeTagSpec("contextSpecific", 1) then
      local nameRelativeToCrlIssuer, err = parser:checkImplicitTag(
        dpName,
        asn.asnTags.universal.set
      )

      if not nameRelativeToCrlIssuer then
        return nil, err
      end

      return andThenAssignToKey(
        "nameRelativeToCrlIssuer",
        parser:parseRelativeDistinguishedName(dpName)
      )
    else
      return nil, parser:makeError(
        errors.x509.invalidType,
        dpName.TAG, "DistrubtionPointName"
      )
    end
  end,

  parseReasons = function(self, parser, reasons)
    local reasons, err =
      parser:checkImplicitTag(reasons, asn.asnTags.universal.bitString)

    if not reasons then
      return nil, err
    end

    return {
      keyCompromise = reasons[1][1] or false,
      cACompromise = reasons[1][2] or false,
      affiliationChanged = reasons[1][3] or false,
      superseded = reasons[1][4] or false,
      cessationOfOperation = reasons[1][5] or false,
      certificateHold = reasons[1][6] or false,
      privilegeWithdrawn = reasons[1][7] or false,
      aACompromise = reasons[1][8] or false,
    }
  end,

  parseCrlIssuer = function(self, parser, crlIssuer)
    local crlIssuer, err = parser:checkImplicitTag(
      crlIssuer,
      asn.asnTags.universal.sequence,
      asn.makeTagSpec("contextSpecific", 2)
    )

    if not crlIssuer then
      return nil, err
    end

    return parseGeneralNames(parser, crlIssuer)
  end,
}

lib.recognizedExtensions[oid.ce.inhibitAnyPolicy] =
  makeExtension("inhibitAnyPolicy", function(_, parser, value)
    return parseSkipCerts(parser, value)
  end)

return lib

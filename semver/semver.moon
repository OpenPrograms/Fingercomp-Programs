_license = [[
   Copyright (c) The python-semanticversion project
   All rights reserved.

   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
   ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
]]

_comment = [[
The use of the library is similar to the original one,
check the documentation here: https://python-semanticversion.readthedocs.io/en/latest/
]]

import concat, insert, unpack from table

toInt = (value) ->
  if tn = tonumber value
    tn, true
  else
    value, false

hasLeadingZero = (value) ->
  value and value[1] == '0' and tonumber value and value != '0'

baseCmp = (x, y) ->
  return 0 if x == y
  return 1 if x > y
  return -1 if x < y

identifierCmp = (a, b) ->
  aCmp, aInt = toInt a
  bCmp, bInt = toInt b

  if aInt and bInt
    baseCmp aCmp, bCmp
  elseif aInt
    -1
  elseif bInt
    1
  else
    baseCmp aCmp, bCmp

identifierListCmp = (a, b) ->
  identifierPairs = {a[i], b[i] for i = 1, #a when b[i]}
  for idA, idB in pairs identifierPairs do
    cmpRes = identifierCmp(idA, idB)
    if cmpRes != 0
      return cmpRes
  baseCmp(#a, #b)

class Version
  @versionRe: (s) =>
    mjr, mnr, pch, rmn = s\match '^(%d+)%.(%d+)%.(%d+)(.*)$'
    return nil unless mjr
    add, r = rmn\match '^%-([0-9a-zA-z.-]+)(.*)$'
    if add
      rmn = r
    meta, r = rmn\match '^%+([0-9a-zA-Z.-]+)(.*)$'
    if meta
      rmn = r
    if #rmn > 0
      return nil
    mjr, mnr, pch, add, meta

  @partialVersionRe: (s) =>
    mjr, rmn = s\match '^(%d+)(.*)$'
    return nil unless mjr
    mnr, r = rmn\match '^%.(%d+)(.*)$'
    if mnr
      rmn = r
    pch, r = rmn\match '^%.(%d+)(.*)$'
    if pch
      rmn = r
    add, r = rmn\match '^%-([0-9a-zA-Z.-]*)(.*)$'
    if add
      rmn = r
    meta, r = rmn\match '^%+([0-9a-zA-Z.-]*)(.*)$'
    if meta
      rmn = r
    if #rmn > 0
      return nil
    mjr, mnr, pch, add, meta

  new: (versionString, partial=false) =>
    major, minor, patch, prerelease, build = unpack @parse versionString, partial

    @major, @minor, @patch, @prerelease, @build, @partial = major, minor, patch, prerelease, build, partial

  _coerce: (value, allowNil=false) =>
    return value if value == nil and allowNil
    tonumber value

  next_major: =>
    if @prerelease and @minor == 0 and @patch == 0
      Version concat {tostring x for x in {@major, @minor, @patch}}, '.'
    else
      Version concat {tostring x for x in {@major + 1, 0, 0}}, '.'

  next_minor: =>
    if @prerelease and @patch == 0
      Version concat {tostring x for x in {@major, @minor, @patch}}, '.'
    else
      Version concat {tostring x for x in {@major, @minor + 1, 0}}, '.'

  next_patch: =>
    if @prerelease
      Version concat {tostring x for x in {@major, @minor, @patch}}, '.'
    else
      Version concat {tostring x for x in {@major, @minor, @patch + 1}}, '.'

  coerce: (versionString, partial=false) =>
    baseRe = (s) ->
      mjr, rmn = s\match '^(%d+)(.*)$'
      return nil unless mjr
      t = mjr
      mnr, r = rmn\match '^%.(%d+)(.*)$'
      if mnr
        rmn = r
        t ..= '.' .. mnr
      pch, r = rmn\match '^%.(%d+)(.*)$'
      if pch
        rmn = r
        t ..= '.' .. pch
      s, t

    match, matchEnd = baseRe versionString
    error 'Version string lacks a numerical component: %s'\format versionString unless match
    version = versionString\sub 1, #matchEnd
    if not partial
      while ({version\gsub('.', '')})[2] < 2
        version ..= '.0'

    if #matchEnd == #versionString
      return Version version, partial

    rest = versionString\sub #matchEnd + 1

    rest = rest\gsub '[^a-zA-Z0-9+.-]', '-'

    prerelease, build = nil, nil

    if rest\sub(1, 1) == '+' then
      prerelease = ''
      build = rest\sub 2
    elseif rest\sub(1, 1) == '.' then
      prerelease = ''
      build = rest\sub 2
    elseif rest\sub(1, 1) == '-' then
      rest = rest\sub 2
      if p1 = rest\find '+'
        prerelease, build = rest\sub(1, p1 - 1), rest\sub(p1 + 1, -1)
      else
        prerelease, build = rest, ''
    elseif p1 = rest\find '+' then
      prerelease, build = rest\sub(1, p1 - 1), rest\sub(p1 + 1, -1)
    else
      prerelease, build = rest, ''

    build = build\gsub '+', '.'

    if prerelease and prerelease != ''
      version ..= '-' .. prerelease
    if build and build != ''
      version ..= '+' .. build

    return @@ version, partial

  parse: (versionString, partial=false, coerce=false) =>
    if not versionString or type(versionString) != 'string' or versionString == ''
      error 'Invalid empty version string: %s'\format versionString

    versionRe = if partial
      @@partialVersionRe
    else
      @@versionRe

    major, minor, patch, prerelease, build = versionRe @@, versionString
    if not major
      error 'Invalid version string: %s'\format versionString

    if hasLeadingZero major
      error 'Invalid leading zero in major: %s'\format versionString
    if hasLeadingZero minor
      error 'Invalid leading zero in minor: %s'\format versionString
    if hasLeadingZero patch
      error 'Invalid leading zero in patch: %s'\format versionString

    major = tonumber major
    minor = @_coerce minor, partial
    patch = @_coerce patch, partial

    if prerelease == nil
      if partial and build == nil
        return {major, minor, patch, nil, nil}
      else
        prerelease = {}
    elseif prerelease == ''
      prerelease = {}
    else
      prerelease = [x for x in prerelease\gmatch '[^.]+']
      @_validateIdentifiers prerelease, false

    if build == nil
      if partial
        build = nil
      else
        build = {}
    elseif build == ''
      build = {}
    else
      build = [x for x in build\gmatch '[^.]+']
      @_validateIdentifiers build, true

    {major, minor, patch, prerelease, build}

  _validateIdentifiers: (identifiers, allowLeadingZeroes=false) =>
    for item in *identifiers do
      if not item
        error 'Invalid empty identifier %s in %s'\format item, concat identifiers, '.'
      if item\sub(1, 1) == '0' and tonumber(item) and item != '0' and not allowLeadingZeroes
        error 'Invalid leading zero in identifier %s'\format item

  __pairs: =>
    pairs {@major, @minor, @patch, @prerelease, @build}

  __ipairs: =>
    ipairs {@major, @minor, @patch, @prerelease, @build}

  __tostring: =>
    version = tostring @major
    if @minor != nil
      version ..= '.' .. @minor
    if @patch != nil
      version ..= '.' .. @patch
    if @prerelease and #@prerelease > 0 or @partial and @prerelease and #@prerelease == 0 and @build == nil
      version ..= '-' .. concat @prerelease, '.'
    if @build and #@build > 0 or @partial and @build and #@build == 0
      version ..= '+' .. concat @build, '.'
    return version

  _comparsionFunctions: (partial=false) =>
    prereleaseCmp = (a, b) ->
      if a and b
        identifierListCmp(a, b)
      elseif a
        -1
      elseif b
        1
      else
        0

    buildCmp = (a, b) ->
      if a == b
        0
      else
        'not implemented'

    makeOptional = (origCmpFun) ->
      altCmpFun = (a, b) ->
        if a == nil and b == nil
          0
        else
          origCmpFun(a, b)
      altCmpFun

    if partial
      {
        baseCmp
        makeOptional baseCmp
        makeOptional baseCmp
        makeOptional prereleaseCmp
        makeOptional buildCmp
      }
    else
      {
        baseCmp
        baseCmp
        baseCmp
        prereleaseCmp
        buildCmp
      }

  __compare: (other) =>
    comparsionFunctions = @_comparsionFunctions(@partial or other.partial)
    comparsions = {
      {comparsionFunctions[1], @major, other.major}
      {comparsionFunctions[2], @minor, other.minor}
      {comparsionFunctions[3], @patch, other.patch}
      {comparsionFunctions[4], @prerelease, other.prerelease}
      {comparsionFunctions[5], @build, other.build}
    }

    for cmpField in *comparsions do
      cmpFun, selfField, otherField = unpack cmpField
      cmpRes = cmpFun(selfField, otherField)
      if cmpRes != 0
        return cmpRes

    return 0

  __compareHelper: (other, condition, notimplTarget) =>
    cmpRes = @__compare other
    if cmpRes == 'not implemented'
      return notimplTarget
    condition cmpRes

  __eq: (other) =>
    c = (x) -> x == 0
    @__compareHelper other, c, false

  __lt: (other) =>
    c = (x) -> x < 0
    @__compareHelper other, c, false

  __le: (other) =>
    c = (x) -> x <= 0
    @__compareHelper other, c, false


class SpecItem

  @KIND_ANY: '*'
  @KIND_LT: '<'
  @KIND_LTE: '<='
  @KIND_EQUAL: '=='
  @KIND_SHORTEQ: '='
  @KIND_EMPTY: ''
  @KIND_GTE: '>='
  @KIND_GT: '>'
  @KIND_NEQ: '!='
  @KIND_CARET: '^'
  @KIND_TILDE: '~'

  @KIND_ALIASES: {
    [@@KIND_SHORTEQ]: @@KIND_EQUAL
    [@@KIND_EMPTY]: @@KIND_EQUAL
  }

  @reSpec: (s) ->
    chr, v = s\match '^(.*)(%d.*)$'
    if not (
        chr == '<' or
        chr == '<=' or
        chr == '' or
        chr == '=' or
        chr == '==' or
        chr == '>=' or
        chr == '>' or
        chr == '!=' or
        chr == '^' or
        chr == '~')
      nil
    else
      chr, v

  new: (requirementString) =>
    @kind, @spec = unpack @parse requirementString

  parse: (requirementString) =>
    if not requirementString or type(requirementString) != 'string' or requirementString == ''
      error 'Invalid empty requirement specification: %s'\format requirementString

    if requirementString == '*'
      return {@@KIND_ANY, ''}

    kind, version = @@reSpec requirementString
    if not kind
      error 'Invalid requirement specification: %s'\format requirementString

    kind = @@KIND_ALIASES[kind] or kind

    spec = Version version, true
    if spec.build != nil and kind != @@KIND_EQUAL and kind != @@KIND_NEQ
      error 'Invalid requirement specification %s: build numbers have no ordering'\format requirementString

    {kind, spec}

  match: (version) =>
    switch @kind
      when @@KIND_ANY
        true
      when @@KIND_LT
        version < @spec
      when @@KIND_LTE
        version <= @spec
      when @@KIND_EQUAL
        version == @spec
      when @@KIND_GTE
        version >= @spec
      when @@KIND_GT
        version > @spec
      when @@KIND_NEQ
        version != @spec
      when @@KIND_CARET
        @spec <= version and version < @spec\next_major!
      when @@KIND_TILDE
        @spec <= version and version < @spec\next_minor!
      else
        error 'Unexpected match kind: %s'\format @kind

  __tostring: =>
    @kind .. @spec

  __eq: (other) =>
    @kind == other.kind and @spec == other.spec


class Spec
  new: (specsStrings) =>
    if type(specsStrings) == 'string'
      specsStrings = {specsStrings}
    subspecs = [@parse spec for spec in *specsStrings]
    @specs = {}
    for subspec in *subspecs
      for spec in *subspec
        insert @specs, spec

  parse: (specsString) =>
    [SpecItem x for x in specsString\gmatch '[^,]+']

  match: (version) =>
    for spec in *@specs
      if not spec\match version
        return false
    true

  filter: (versions) =>
    i = 0
    iter = ->
      while true do
        i += 1
        version = versions[i]
        return nil unless version
        if @match version
          return version

    iter

  select: (versions) =>
    options = [x for x in @filter versions]
    if #options > 0 then
      max = options[1]
      for ver in *options
        if max < ver
          max = ver
      max
    else
      nil

  __index: (k) =>
    if @match k
      true
    else
      nil

  __pairs: =>
    pairs @specs

  __ipairs: =>
    ipairs @specs

  __tostring: =>
    concat {tostring spec for spec in *@specs}, ','

  __eq: (other) =>
    for selfSpec in *@specs
      s = false
      for otherSpec in *other.specs
        if selfSpec == otherSpec then
          s = true
          break
      if not s
        return false
    return true

compare = (v1, v2) ->
  baseCmp Version v1, Version v2

match = (spec, version) ->
  Spec(spec)\match Version version

validate = (versionString) ->
  ({Version\parse versionString})[1]


{
  :Spec
  :SpecItem
  :Version
  :compare
  :match
  :validate
}

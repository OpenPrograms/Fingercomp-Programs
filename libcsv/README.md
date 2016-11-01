# libcsv
*A CSV parser*

## Description
Returns a function that accepts the string to decode as the first argument and returns the decoded value.

```lua
local parse = require("csv")
print(require("serialization").serialize(parse("aaa,bbb,ccc,ddd\neee,fff,ggg,hhh")))
```

Fully implements the [RFC 4180](https://tools.ietf.org/html/rfc4180).

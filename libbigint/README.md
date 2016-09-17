# libbigint
*May the big numbers be with you.*


## Description
When required, the `bigint` function is returned for creation big integers. Those are the table values with a metatable assigned to them that provides some metamethods:

* `__add` — the addition operation (`a + b`)
* `__sub` — the subtraction operation (`a - b`)
* `__mul` — the multiplication (`a * b`)
* `__div` — the division (`a / b`)
* `__mod` — the modulo (`a % b`)
* `__unm` — the unary minus (inversion, `-a`)
* `__eq` — test for equality (`a == b`)
* `__lt` — the "less than" (or "greater than") comparsion (`a < b`, `b > a`)
* `__le` — the "less/greater than or equal to" comparion (`a <= b`, `b >= a`)
* `__tostring` returns the decimal number representation (as string): `tonumber(a)`

As you can see, all Lua 5.2 operators are supported.

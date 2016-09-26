# der-decoder
*Suprisingly, it does what the name says: decodes DER-encoded data*.

## Description
The library returns a decoder function: `decode(data: string, kwargs: table)`

The first argument is the data that should be decoded. The second argument specifies additional parameters for the decoder.

Currently, only the `content` field is used: it's the table of tag codes that will be used in specified order.

E.g., if you run this piece of code:

```lua
decode(data, {context={
  0x02,
  0x09
}})
```

the first tag with the "context-specific" class will be decoded as an integer, and the second one will be decoded as a real number.

### Usage
I use this library to decode X.509 certificates (the standard of a very common certificate encoding, e.g., used in TLS). You, though, may have your own ideas on how to use this library. :)

I'd not recommend to encode something with the DER, though, as it's not that space-efficient.

## License
This program uses the Apache 2.0 license. The text of the license can be obtained [here](http://www.apache.org/licenses/LICENSE-2.0).

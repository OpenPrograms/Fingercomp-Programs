# libhttp
*A HTTP/HTTPS 1.1 library.*

This is a library (obviously) that returns a HTTP request function. It tries to mimic behaviour of `component.internet.request`, at the same time enabling to choose a request method to use (`GET`, `POST`, `PATCH`, etc.).

## Usage

* `http(url: string[, body: string[, headers: table[, method: string]]])` — starts a new request.
* `http(url: string[, kwargs: table])` — does pretty much the same, but accepts a table of arguments.

All options of kwargs are optional. Here's the example of a full kwargs table:

```lua
{
  body = "Hi there\n",
  headers = {
    ["Content-Type"] = "application/json",
  },
  method = "PATCH"
}
```

The function returns a table of functions:

* `response.close()` — closes the connection.
* `response.finishConnect(): boolean[, string]` — returns whether the connection is established.
* `response.read([n: number]): string or nil` — reads a certain amount of data from the buffer.
* `response.response(): number, string, table` — returns a status code, status text, and headers.

All headers returned by `response.response()` are Train-Cased, so that you don't need to worry about that.

The response body is read all and stored in the buffer. If you don't specify any arguments for `response.read`, it will return *the whole buffer*. This is different from "vanilla" `request` method, where the data is returned as chunks of random length.

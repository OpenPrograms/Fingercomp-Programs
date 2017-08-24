# Libaevent
*An advanced event library*

Available for downloading on the [Hel Repository](https://hel.fomalhaut.me/#packages/libaevent).

The library was written by @LeshaInc. I only packaged it here so it's now available to be downloaded with OPPM, and wrote the documentation.

## Advantages
Advantages over the standard event library:
* It features the thing I really needed: pushing event with payload of **any** types, including functions and tables.
* Priorities system.
* The event system is *local*, which means you can have multiple event engines running simulateously, and the events *won't* interfere with other engines.
* Events are classes.
* Events are *cancellable*, cancelling one makes it not to go any further.

## Using the library
The library returns an `Engine` *class*, which has to be initialized. Generally you'll need to do something like this (note the parentheses at the end):

```lua
local EvEngine = require("aevent")()
```

### Methods

The resulting instance has the following methods:

| Method | Description |
| ------ | ----------- |
| `engine:event(name: string)` | Creates an event with a name `name`. It may be then called to get an instance of the event. |
| `engine:event(name: string)(data: table[, once: bool])` | Returns an instance of the event with the specified payload. The | `once` arguments makes the event be processed by only one subscriber. Generally you'd use `instance{test="test"}`. |
| `engine:event(name: string)(data: table[, once: bool]):cancel()` | Cancels an event. |
| `engine:event(name: string)(data: table[, once: bool]):get()` | Returns the event's payload. |
| `engine:push(evtinst: table)` | Pushes the event instance. |
| `engine:subscribe(name: string, priority: number, handler: function)` | Assigns a callable (function or table with defined `__call`) to an event with a specific priority. |
| `engine:stdEvent(eventName: string, event: table)` | Registers a new listener that will listen for the given event, and will fire instance of the given event. |
| `engine:timer(interval: number, event: table[, times: number])` | Creates a new timer that will push the given event on every tick. |
| `engine:__gc()` | Unregisters all listeners for the computer signals. Call this if the `__gc` metamethod is disabled. |

### Sample code
```lua
local EvtEngine = require("aevent")()

local Event1 = EvtEngine:event("event1")

EvtEngine:subscribe("event1", 0, function(evt)
  print("0 callback!", evt.test) -- If the event is indexed, and the index is none of
                  -- standard keys (e.g., cancel), it'll look for the
                  -- value in the event's payload.
  evt:cancel()
end)

EvtEngine:subscribe("event1", 1, function(evt)
  print("1 callback!", evt.test)
end)

EvtEngine:push(Event1{
  test = "Hello!"
})

--> 0 callback!     Hello!
```

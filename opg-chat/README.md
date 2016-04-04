# opg-chat
*The powerful chat program*

![Screenshot of the program](http://i.imgur.com/pskyEl9.png)

### Features
* Channels
* Wireless keyboard support
* Modules
* Network interface
* Separated buffers
* Configuration file
* ...

### Requirements
* Data card or OpenSecurity data block. If you will be missing all of them, the network interface will be disabled.
* OpenPeripheral terminal glasses bridge connected via adapter.
* OpenPeripheral terminal glasses connected to a bridge.

# Usage
## Installation
The things you'll need are a terminal bridge, terminal glasses, an adapter and either a data card or a data block.
Connect an adapter to a computer, place a bridge next to a adapter. Insert your data card into a computer if you've crafted it, or connect your data block to a computer.
Now type `edit /etc/chat.json` and configure this program as you wish. You'll probably want to at least change a list of admins to be able to stop the chat.
When you're finally done, simply run `opg-chat`.

## Basic usage
**To enter a message, type $$<msg here> in the chat and press [Enter]**.
**To run a chat command, do the same, but with **`/`** before message**.
(You can also use a wireless keyboard, no need to type `$$` then.)

### Some commands you should know:
* `stop` - as you might guess, this command stops the program. Available for admins only.
* `join <chan>` - join a channel.
* `part [chan/tab]` - leave a channel. And yes, you can't leave a main channel. Sorry about that.
* `help [command]` - request help. With no arguments given, list all the commands.
* `page [lines]` - move in a channel history. Positive values move the chat up for the specific number of lines, negative values move the chat down.
  * You can also press PgUp/PgDn keys if you use a wireless keyboard.

# Advanced tweaking
## Modules
If you're not satisfied with the included modules, you can also write your own! Create a file with an extension `.module` in `/usr/lib/chat-modules/` and do magic.
Use the included modules as an example.

### Environment
* `storage` - a temporary memory for all of your stuff. Can be also used for cross-module communication.
* `apcall(func, args...)` - an advanced pcall, cuts off an unnecessary stuff, leaving only a reason. It used in modules to show an error reason to users.
* `createChannel` - this function is actually for internal use only, don't use it.
* `addUser(user)` - add a user with the specific name.
* `join` - don't use this function either, but instead use...
* `joinN(chan, user)` - ...this one instead. Makes a user join a channel, sends notifications and events. Creates a channel if it doesn't exist.
* `part` - an internal function too, use:
* `partN(chan, user[, partMsg])` - makes a user leave a channel.
* `quitN(user[, quitMsg])` - makes a user leave all channels.
* `sendMsgChan(chan, user, msg[, recipients])` - makes a user send a message to a channel. You can also specify a table with recipients if you need so.
* `sendMsgChanN(chan, user, msg)` - do some additional checks, for example, if a user has sufficient rights, and do the same as the previous function if all's OK.
* `addObject(surface, objName, funcKey, ...)` - the preferred way to add new objects to the glasses. Stores an object under a specified name so it could be accessed later.
  * **Note:** `funcKey` should have a `string` type.
* `getActiveChannel(user)` - get an "active" channel (user has a tab with that channel open).
* `bridge` - a bridge proxy.
* `surfaces` - a table which contains users' surfaces.
```lua
surfaces[user] = {
  surface = {...}, -- an actual surface
  objects = {...} -- a table with objects added to surface
}
```
* `users` - a table containing users added with the `addUser` function.
* `channels` - a table containing channels.
* `commands` - a table containing all registered commands.
* `isin` - a simple but still very useful function. Iterates over a table and searches for a specific value. Returns `true, <key>` on success or `false` otherwise.
* `cfg` - a configuration. It auto-saves every minute and also on exit.
* `setMode(chan, user, mode[, arg])` - sets a mode. Errors on failtures. `mode` should be `±<modeLetter>`, ex.: `+o`, `-h`.
* `modes` - a table containing modes.
* `getLevel(chan, user)` - returns user access level mask.
* `checkLevel(chan, user, levels, any)` - checks if a user has requested access. `levels` is a table containing access levels (`{OP, ADMIN, SERVER}`). If `any` is `true`, a user should have `any` of given access levels. Otherwise, a user should have *all* of them.
* `reqcom(componentName, required[, msg])` - get a component proxy. If `required` is `false`, return a dummy component and `false`. Otherwise, error. Print a `msg` if component is not available.
* `copy(tbl)` - returns a copy of a table.
* `_FILE` - a filename.
* `_MODULE` - a module name (a filename without extension).
* `NORMAL`, `VOICE`, `HALFOP`, `OP`, `ADMIN`, `SERVER` - access levels.
* `PREFIXES` - a table containing prefixes for levels.
* `addListener(eventName, name, func)` - add an event listener with a specific name. Will be automatically ignored on program exit.
* `delListener(eventName, name)` - remove an event listener.
* `command {args}` - add a new command. Args is an table with the following keys:
```lua
{
  name = "command", -- a command, required
  level = NORMAL, -- who is allowed to use this command, required
  help = "A short description of this command",
  doc = [[A long documentation for this command]],
  func = function(eventName, channelWhereThisCmdWasSent, userWhoSentThisCommand, rawCommand, commandName, args...)
    print("A function which will be called on command")
  end
}
```

## Network interface (network.module)
This module allows to create your own chat bots.
It supports both types of modems. Be aware of a spoofing card from Computronics, as it allows to specify a custom address.

### Configuration
There is a "net" section in a configuration file (`/etc/chat.json`). Here is an example:
```json
"net": {
  "enabled": true,
  "modemStrength": 400,
  "ports": {
    "6667": true,
    "6666": ["519187"]
  }
}
```
* `enabled` controls whether the network module should be enabled.
* If a modem is wireless, its strength will be set to the value of `modemStrength` setting.
* `ports` is a list with ports which the program will listen.
  * Left part (`"6667"`), obviously, is a port to listen on.
  * Right part can be one of two values: `true`, which means a port is *not* filtered, or a list with white-listed addresses (or their parts). In this example, the program will accept connections on a port 6667 only from sender starting with `"519187"`.

### Commands
* `"userName", "auth", <pass>` - authenticate to the server.
* `"userName", "msg", <someMsg>` - send message or command to the server.
* `"userName", "quit"[, reason]` - close a connection.

### Passwords
As you could see, you need a password to authenticate. Where should you take it?
* If there is no password for a username (or that username hasn't ever been used), you should give an empty string (`""`) as a password.
* But if there is, you should use it as a `<pass>` argument.
* Use `/pass <pass>` to set a password for a username. If you omit the argument, a password will be unset.
  * Passwords are saved in a configuration file as their MD5 hashes.

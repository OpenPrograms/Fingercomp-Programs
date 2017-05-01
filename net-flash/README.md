# net-flash
*A simple remote EEPROM "flasher".*

Do you know how drone or microcontroller program debugging is done? Probably
yes: you pick up the drone, swap the EEPROM with another one, insert this
EEPROM into a computer or a server, `flash` the new BIOS, take the flashed
EEPROM back, swap it again to insert it into the drone, place the drone at
required position, start the drone and hope the program you've flashed will
work.

It's okay when you need to do this once, but when you need to do this quite A
LOT of times this becomes **really** tedious and nasty.

And this 4096 B code size limit just makes you crazy, doesn't it?

Well, maybe the program I'm going to present won't fully remove the code size
restriction, but at least it will make the debugging a whole lot easier.

Before you can use this program, you have to flash the provided BIOS. It's a
really simple program that waits for the program sent over the network (yes,
you have to install the wireless card into the drone or microcontroller),
remembers and runs it.

**Don't forget to replace the default ADDR variable in the code with the actual
address of the modem you want to use.** Or the drone would just ignore
all commands you send.

Power on the drone and return to the host machine. Now you can use
the `net-flash` command. Run it without arguments -- you'll get a simple help
text.

The only required argument is the source. The program can either read from a
file (if you pass the path to the file) or from stdin (it's just a simple `-`).

There's not much to say on the former option. The latter is more interesting.
If you just run `net-flash -`, you'll be prompted for the command to send to
the remote host. But you can use piping. For example, to keep configuration and
program separate from each other, you can use `cat options.cfg program.lua` to
concatenate those two files, and pass the output to the `net-flash` so the
remote receives the concatenated output.

```
$ cat options.cfg program.lua | net-flash -
```

Pretty cool, isn't it?

Of course, this program has to have some options for you to tweak.

* `--c` is the chunk size. You want to keep it at least slightly below the modem max packet size, or the program would just crash. `4096` will be used if not given.
* `--port` is the, uhhh, port to use. Obviously you have to change the port on the remote host if you want to use this option.
* `-r` or `--response` make the program wait for the drone response (it tells if the program crashed or not, and gives the program returned values). You can specify the timeout if you want (if you don't, the program would wait indefinitely). If you don't give the option, though, the program would instantly exit without waiting for the response.
* `--addr` makes the program not to broadcast messages but to send specifically to the remote modem instead.

Perhaps you would expect more, but that's all. Have fun programming drones and microcontrollers -- it's easier than you think.

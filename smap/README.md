# smap
**A Simple Minecraft Audio Player**

## What it does?
It plays audio, does it quite well (oh, okay, not as well as I want).

## General info
There are input modules and output modules.

### Input modules
They read a file and convert it to internal format.

Currenlty supported audio files are:
* `nbs`: Minecraft Note Block Studio files.
* `midi`: a clumsy module, mostly a copypaste from Sangar's midi.lua code. Reads MIDI files, and plays it.

### Output modules
They convert an internal format audio to actual sounds!

Currently supported devices are:
* `inoteblock`: Computronics' Iron Note Block. Btw, it's a very good thing.
* `pcspkr`: `computer.beep`'s.
* `beep`: Computronics' beep card.

## Big thanks to:
* TxN, for his NBS player code,
* Sangar, for his amazing mod, and midi.lua code as well,
* FluttyProger, for helping and motivating me to fight against bugs.

## License
Some pieces of this program use the Apache 2.0 license. Such files have a comment attached at the top with the copyright information. The text of the license can be found [here](http://www.apache.org/licenses/LICENSE-2.0)

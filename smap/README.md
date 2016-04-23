# smap
**A Simple Minecraft Audio Player**
(Totally simply)

## What it does?
It plays audio, does it quite well (oh, okay, not as well as I want).

And yeah, it is a library.

## General info
There are modules. To be exact, two types of them: input modules, and output modules.

### Input modules
They read a file and convert it into internal format.

Currenlty supported audio files are:
* `nbs`: Minecraft Note Block Studio files.
* `midi`: a clumsy module, mostly a copypaste from Sangar's midi.lua code. Reads MIDI files, and plays it... **Should** play somewhen in future.

### Output modules
They convert an internal format audio to the actual sounds!

Currently supported devices are:
* `inoteblock`: Computronics' Iron Note Block. Btw, it's a very good thing.
* `pcspkr`: `computer.beep`'s.

## Big thanks to:
* TxN, for his NBS player code,
* Sangar, for his amazing mod, and midi.lua code as well,
* FluttyProger, for helping and motivating me to fight against bugs.

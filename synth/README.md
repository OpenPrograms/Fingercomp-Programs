# synth
*An easy-to-use interface to the sound card.*

### Libraries
This program uses a lot of libraries written by other people.

* `GUI.lua`, a wonderful GUI library written by @IgorTimofeev.
  * `advancedLua.lua`
  * `color.lua` -- modified by me to work on Lua 5.3
  * `image.lua` -- stripped the depenedncy on OCIF as I don't need it
* `doubleBuffering.lua`, a library; provides a buffer that, when flushed, tries to use as less draw instructions as possible, drawing complex things really fast. Also written by @IgorTimofeev.
* A bundled beautiful plotter library written by @LeshaInc; also modified by me: it now actually works and uses the doubleBuffering library.

![Screenshot](https://i.imgur.com/Ahxvlv2.png)

# Fingercomp's programs
This is a place where hopefully brilliant ideas become programs.

It's been a long time since I've really updated anything here.
Many things changed, so some programs may no longer work correctly.
If you spot a bug, please *do* open a issue.

## Programs
Each package resides in its own directory.
Look there for more information.

* `libsemver`
  * A MoonScript port of a parser of semantic version strings originally written in Python.
* `libaevent`
  * An advanced event library.
* `libder-decoder`
  * Decodes data encoded using Distinguished Encoding Rules, a subset of ASN.1. For example, x.509 certificates.
* `libcsv`
  * A CSV parser.
* `charts`
  * Progress bars and histograms with extra precision.
* `particly`
  * A really simple program that uses a Particle Card to "draw" bitmaps in the world.
* `pipedream`
  * A simple graphical program.
* `railtank`
  * A fancy tank monitoring program.
* `sniff`
  * A network sniffer.
* `stars`
  * A simple graphical program.
* `eumon`
  * An EU storage monitor.
* `ffp`
  * A PCM (or WAV if the provided converter is used) player.
* `lumber`
  * A basic lumberjack program for a robot which uses an axe that can chop the whole tree, e.g., thaumcraft's axe of the stream.
* `synth`
  * A powerful interface to the sound card.
* `libtls`
  * An implementation of TLS 1.2.
* `libtls13`
  * An implementation of TLS 1.3.
* `libhttp`
  * An incomplete HTTP/HTTPS 1.1 library implemented on top of TCP sockets. May be useful in some awkward cases.

### Repackaged
Programs I didn't write but had to repackage here as dependencies.

* `lua-lockbox`
  * The most awesome pure Lua cryptography toolkit that I've ever found.
* `libbigint`
  * Enables one to have *very* big integers, storing them in a metatable. Basic arithmetic operations (like abs, addition, division, etc.) are supported.

### Unmaintained
Programs I have no interest in maintaining.

* `nn`
  * Nanomachines control program.
* `gist`
  * Gist downloader and uploader.
* `game-of-life`
  * My implementation of Life.
* `opg-chat`
  * IRC-like OpenPeripheral glasses chat.
* `smap`
  * A *s*imple *M*inecraft *a*udio *p*layer.

## License
This repository's files, unless subject to the exceptions below, are licensed under the [Apache 2.0 license](https://www.apache.org/licenses/LICENSE-2.0.txt).
The exceptions are as follows:
- The software listed above as repackaged.
- Files bearing copyright notices.
  - Such files are provided under the terms of the license specified therein.
- Files in a directory containing a `LICENSE` file, or a subdirectory thereof.

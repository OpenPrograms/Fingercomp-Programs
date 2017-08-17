# Fingercomp's programs
This is a place where hopefully brilliant ideas become the programs.

## Programs
*(open programs' directories and see their READMEs for more info)*
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
* `lumber`
  * Basic lumberjack program for OC robot which uses an axe that can chop the whole tree, e.g., thaumcraft's axe of the stream.
* `libsemver`
  * A MoonScript port of a parser of semantic version strings originally written in Python. **Available on the Hel Repository**.
* `libaevent`
  * An advanced event library. **Available on the Hel Repository**.
* `libbigint`
  * **Not mine!** Enables one to have *very* big integers, storing them in a metatable. Basic arithmetic operations (like abs, addition, division, etc.) are supported. **Available on the Hel Repository**.
* `libder-decoder`
  * Decodes the data encoded using Distinguished Encoding Rules, a subset of ASN.1. For example, x.509 certificates. **Available on the Hel Repository**.
* `lua-lockbox`
  * The most awesome pure Lua cryptography toolkit that I've ever found. **Available on the Hel Repository**.
* `libtls`
  * An implementation of TLS 1.2. **Available on the Hel Repository**.
* `libhttp`
  * A HTTP/HTTPS 1.1 library that allows to specify a request method (`GET`, `POST`, `DELETE`, `PATCH`, etc.). **Available on the Hel Repository**.
* `libcsv`
  * A CSV parser. **Available on the Hel Repository**.
* `charts`
  * A charts library (at least it should become such). **Available on the Hel Repository**.
* `particly`
  * A really simple program that uses Particle Card to "draw" bitmaps in the world. **Available on the Hel Repository**.
* `pipedream`
  * A simple graphical program. **Available on the Hel Repository**.
* `railtank`
  * A fancy tank monitoring program. **Available on the Hel Repository**.
* `sniff`
  * A network sniffer. **Available on the Hel Repository**.
* `stars`
  * A simple graphical program. **Available on the Hel Repository**.
* `eumon`
  * An EU storage monitor.
* `synth`
  * A powerful interface to the sound card.
* `ffp`
  * A PCM (or WAV if the provided converter is used) player.

## How to install
You can, of course, just copy-paste files, but that's really inconvenient.
If you have an internet card, you can use *package managers* to make it really
easy. Those will handle downloading all files and installing dependencies for
you.

There are two package managers that work with OpenPrograms repositories: `hpm`
that's bundled with the `oppm` module, and `oppm`.

`oppm` can be found on the oppm floppy disk included in OpenComputers. Combine
interweb and a floppy to get it, insert the floppy into a disk drive and run
`install`. Then you can run `oppm install program` to install `program`.

### What is the Hel Repository?
This is yet another OpenComputers program repository written by @moonlightowl and me. The key features are:
* Sane versioning
* Specific dependency versions
* Public API

Also we have the Hel Repository package manager called `hpm`. It's great, really.
* Resolves dependencies.
* Allows to be extended by modules.
* Makes it easy to develop your complex programs with its manifest feature.
* The OpenPrograms module is bundled with hpm. It caches the packages to decrease installation time (no need to use that slow oppm anymore).

But the repository is used not because it's cool. It needs to contain cool
programs and a lot of packages. That's why I publish my programs both here and
on the Hel Repository. If you want to use my library for your program, please
consider using the Hel Repository for this. That'll stop your program from
crashing when the library API changes after update because you can specify the
version of the library that definitely works with your program.

Install hpm using the following command:

```
$ pastebin run vf6upeAN
```

Update oppm cache to be able to install OpenPrograms packages:

```
$ hpm oppm:cache update
```

Install any hpm package...

```
$ hpm install hpm
```

...or OpenPrograms package:

```
$ hpm oppm:install oppm
```

#### Links
* The [GitHub organization](https://github.com/hel-repo).
* The [web interface](https://hel.fomalhaut.me/).
* The topic on [the forums](https://oc.cil.li/index.php?/topic/1116-hel-repository/).

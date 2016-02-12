# gist
*Download and upload files from/to Gist*

## Synopsis
`gist [-p] [--P=mode] [--d=desc] [-sRqQlriG] [--f=filename] <id> [file]`

## Description
This program makes it easy to download and upload files to/from Gist.

## Requirements
* Internet card (HTTP requests have to be enabled in mod's configuration).

## Options
If uploading, pass file list as arguments with the following format: `<path to local file>=<gist filename with .extension>`

* `-p`
  * Upload files to gist.
* `--P=mode` or `--public=mode`
  * **Upload**: `s` mode makes gist to be secret, `p` - public.
* `--d=description` or `--description=description`
  * **Upload**: Set a description for a gist.
* `-s`
  * If uploading, shorten the resulting URL. Else shorten the Github URL given as the first argument.
* `-R`
  * Show URL to a raw file contents.
* `-q`
  * Quiet mode.
* `-Q`
  * Superquiet mode: do not show errors.
* `-l`
  * List files in gist and quit.
* `-r`
  * Override the file even if it exists.
* `-i`
  * Show the file information.
* `-G`
  * Show the gist information.
* `--f=filename` or `--file=filename`
  * Specify the file to work with.

## Examples
* `gist -s -p --P=s --d="Hello, world!" /examples/test.lua=test.lua`
  * Uploads file /example/test.lua to a secret gist with description "Hello, world" and shows the short URL.
* `gist -G https://git.io/example`
  * Gets the gist information.
* `gist 1a3b5b7c9d1e3f5a7b9c`
  * Prints gist's file contents.
* `gist --f=helloworld.c -r https://git.io/example helloworlds/hello.c`
  * Saves the contents of the file helloworld.c in the gist to helloworlds/hello.c, overrides the file if it exists.

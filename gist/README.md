# gist
*Download and upload files from/to Gist*

## Synopsis
`gist [-p] [--P=mode] [--d=desc] [-sRqQlriG] [--f=filename] <id> [file]`

## Description
This program makes it easy to download and upload files to/from Gist.

## Requirements
* Internet card (HTTP requests have to be enabled in mod's configuration).

## Options
If uploading, provide file list as arguments with the following format: `<path to local file>=<gist filename with .extension>`

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
* `-t`
  * Prompt for a GitHub OAuth [personal access token](https://github.com/settings/tokens) (needs to have *gist* scope to work). **Requires OpenComputers 1.6 and higher**.
* `--t=token` or `--token=token`
  * Use the given token. *Not recommended*, since the token will be visible as a plain text. **Requires OpenComputers 1.6 and higher**.
* `--u=gistid`
  * **Upload mode**. Instead of posting a new gist, update the existing one with the given ID. Provide the files to modify as if you were uploading to Gist. *Requires the correct token*, see `-t`. Also **requires OpenComputers 1.6 and higher**.

## Examples
* `gist -s -p --P=s --d="Hello, world!" /examples/test.lua=test.lua`
  * Uploads file /example/test.lua to a secret gist with description "Hello, world" and shows the short URL.
* `gist -G https://git.io/example`
  * Gets the gist information.
* `gist 1a3b5b7c9d1e3f5a7b9c`
  * Prints gist's file contents.
* `gist --f=helloworld.c -r https://git.io/example helloworlds/hello.c`
  * Saves the contents of the file helloworld.c in the gist to helloworlds/hello.c, overrides the file if it exists.
* `gist -t --u=12345678901234567890 -p --d="New description" /new/file=file.lua`
  * Changes the description of the gist with the ID `12345678901234567890` to `New description` and updates contents of the file `file.lua`. Prompts for the GitHub OAuth [personal access token](https://github.com/settings/tokens).
* `gist -s -p --d="Hello, world!" --P=s -t /hello/hello.cpp=hello.cpp`
  * Prompts for the GitHub OAuth [personal access token](https://github.com/settings/tokens) and then uploads the file `hello.cpp` to Gist. Returns a short URL to the gist.

## License
This program uses the Apache 2.0 license. The text of the license can be obtained [here](http://www.apache.org/licenses/LICENSE-2.0).

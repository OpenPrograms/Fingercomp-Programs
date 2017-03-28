# nn
*Gives you control of your nanomachines.*

## Synopsis
`nn [action] [agruments...]`

## Description
This program allows the player to control their's nanomachines.

## Requirements
* Wireless modem card

## Actions
* `get`
  * Show result of the basic test.
* `clear`
  * Turn off all the inputs.
* `test [exclude...]`
  * Run the basic test. Type the inputs you don't want to turn on if you want.
* `init [port]`
  * The main action: sets the response port and initializes program. **Run this first.**
* `g <msg> [other parts...]`
  * Send the message to nanomachines. Show the reply.
* `s <msg> [other parts...]`
  * Send the message to nanomachines. Don't wait for processing and the reply.
* `reset`
  * Clear the testing results.
* `info`
  * Get info about nanomachines.
* `on <input>`
  * Turn on the input.
* `off <input>`
  * Turn off the input.
* `hp`
  * Get player's health.
* `hunger`
  * Get player's hunger and saturation levels.
* `energy`
  * Get nanomachines' energy.
* `usage`
  * Get nanomachines' energy usage.
* `age`
  * Get player's age.
* `name`
  * Get player's name.
* `input`
  * Get max safe and hard max active inputs limits.
* `copy`
  * Save the nanomachines configration to other nanomachines in inventory.
* `efon`
  * Get currently active effects.
* `combo [exclude...]`
  * Run combinatoric test (1-1, 8-14, etc). Tyoe the input nums to exclude them from testing. If you want to exclude a specific combination, type `<first input>-<second input>`. Right part should be greater than left one.
* `getcombo`
  * Get combinatoric test results
* `group`
  * `group set <name> <input> [other inputs...]`
    * Add a group or modify group's settings with the name `<name>`.
  * `group del <name>`
    * Remove a group.
  * `group save`
    * Save the group settings to a file.
  * `group on <name>`
    * Turn on all the inputs in the group with the name `<name>`.
  * `group off <name>`
    * Turn off all the inputs in the group with the name `<name>`.
  * `group list`
    * List groups and their inputs.

## Examples
* `nn combo 1-5 12 8-15`
  * Runs the combinatoric test and excludes input #12 and combinations 1+5 and 8+15 from testing.

## License
This program uses the Apache 2.0 license. The text of the license can be obtained [here](http://www.apache.org/licenses/LICENSE-2.0).

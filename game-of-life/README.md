# Conway's Game of Life implementation for OpenComputers
![Screenshot of the game.](http://i.imgur.com/J7enOnc.png)

* With the simulation paused, use the controls (descibed below) to place or kill cells.
* Press `[Space]` and observe the magic evolution of these cells.

## Rules
* The board updates at specific rate.
* Every update the new generation is displayed.
* The board is a toroidal array (the borders are "glued").
* The board is filled with cells.
* Cells may be either *dead* or *alive*.
* Every cell may have up to 8 neighbors.
* Any live cell with **0-1 neighbors** *dies* (becomes a dead one).
* Any live cell with **2 neighbors** *stays alive* in next generation.
* Any live cell with more than **3 neighbors** *dies*.
* **_Any_** cell with **exactly 3 neighbors** *becomes a live one* (if it was dead) and *stays alive* in the next generation.

### Highlighting
* If cell will *die* on the next generation, it'll be red.
* If cell will *be born* on the next generation, it'll be dark green.
* If cell is *alive* on current and next generations, it will be white.

## Controls
* `[Space]` *Start* or *pause* simulation.
* `[q]` *Quit* the game.
* `[Left Mouse Button]` *Place* a cell (only works if **the simulation is paused**).
* `[Right Mouse Button]` *Kill* a cell (only works if **the simulation is paused**).
* `[Enter]` *Next* generation (only works if **the simulation is paused**).
* `[<]` *Descrease* the speed of the simulation.
* `[>]` *Increase* the speed of the simulation.
* `[c]` Toggle the *highlighting*.
* `[Backspace]` *Clear* the board (only works if **the simulation is paused**).

## Requirements
* T3 screen.
* T3 graphics card.

## License
This program uses the Apache 2.0 license. The text of the license can be obtained [here](http://www.apache.org/licenses/LICENSE-2.0).

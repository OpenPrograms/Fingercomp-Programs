# Conway's Game of Life implemention for OpenComputers
![Screenshot of the game with the simulation paused and the "Hello :-)" text in the middle.](http://i.imgur.com/eAINaIq.png)

## What you should do in this game
* With the simulation paused, use the controls below to place or kill cells.
* Press `[Space]` and observe the magic evolution of these cells.

## Rules
* The board updates at least every 1/10 s.
* Every update the new generation is displayed.
* The board is finite, there's no anything like a toroidal array or such.
* The board is filled with cells.
* Cells may be either *dead* or *alive*.
* Every cell may have up to 8 neighbors.
* Any live cell with **0-1 neighbors** *dies* (becomes a dead one).
* Any live cell with **2 neighbors** *stays alive* in next generation.
* Any live cell with more than **3 neighbors** *dies*.
* **_Any_** cell with **exactly 3 neighbors** *becomes a live one* (if it was dead) and *stays alive* in the next generation.

## Controls
* `[Space]` *Start* or *pause* simulation.
* `[q]` *Quit* the game.
* `[Left Mouse Button]` *Place* a cell (only works if **the simulation is paused**).
* `[Right Mouse Button]` *Kill* a cell (only works if **the simulation is paused**).

## Requirements
* T3 screen.
* T3 graphics card.

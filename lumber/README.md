## A basic lumberjack program for OC robot

```
XX  XX  XX  XX    3 ^
                    |
XX  XX  XX  XX    2 | Height
                    |
XX  XX  XX  XX    1 v
          ← <>[]
            {}
   2       1
<----Width--->
```

The ASCII-picture above represents the farm.

* `XX`: sapling
* `  `: empty block
* `<>`: robot
* `[]`: chest
* `{}`: charger
* The `←` shows robot's facing.

Download the program on the robot and type `edit /usr/bin/lumber.lua` to edit settings.

One'll need to change `W` and `H` to the values that are calculated according to the picture above.

The `INTERVAL` settings makes a robot wait a certain time before it'll begin the next cycle. If the interval is set to `false`, robot will only wait time required to fully recharge.

Robot will also drop the tool in the chest under it when it completes a cycle. This could be used to recharge or repair the tool.

The tool is an axe that can chop the whole tree, not only one wood block.

### License
This program uses the CC0 1.0 license, see the `LICENSE` file for more details about the license.

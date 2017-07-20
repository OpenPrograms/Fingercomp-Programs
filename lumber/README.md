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

Download the program on the robot and type `edit /usr/bin/lumber.lua` to edit
settings.

You need to change `W` and `H` to the values that are calculated according to
the picture above.

The `INTERVAL` settings makes a robot wait a certain time before it'll begin
the next cycle. If the interval is set to `false`, robot will only wait until
fully recharged.

Robot will also drop the tool in the chest under it when it completes a cycle,
unless the `DROPTOOL` setting is set to `false`. This could be used to recharge
or repair the tool.

The tool is an axe that can chop the whole tree, not only one wood block.

**You also need to insert some saplings in the bottom-right slot of robot
inventory, and a log in the previous one.** Otherwise the program won't be
able to distinguish a sapling from a log, and so the robot won't chop the
trees.

### License
This program uses the CC0 1.0 license, see the `LICENSE` file for more details about the license.

# ffp
*An audio player*

Plays PCM files (the provided converter converts WAV files, too).

Available for downloading on the [Hel Repository](https://hel.fomalhaut.me/#packages/ffp).

## Usage
### Playing PCM files directly
```
ffp $path $depth $sample_rate $channels $window_size $window_step $duration
```

* `$path` - path to a PCM file
* `$depth` - bit depth
* `$sample_rate` - sample rate
* `$channels` - amount of sound card channels to use (8 by default)
* `$window_size` - window size, in samples (1024 by default)
* `$window_step` - does something, probably (1 by default)
* `$duration` - how much to play, in seconds (by default the whole file)

### Converting a PCM file
Twice as faster than playing directly.

Run the script not on an OpenComputers machine. The usage remains the same,
just redirect the output to a file.

You can play the output file using the following command.

```
ffp --load $path $duration
```

* `$path` - path to the output file
* `$duration` - how much to play, in seconds (the whole file if empty)

### Converting a WAV file
This is the fastest option that uses numpy's FFT implementation to convert WAV
files. The same audio file took more than 20 minutes to convert using the
previous converter, and a minute using the converter written in Python.

Requires Python 3, NumPy, SciPy.

```
./converter.py $path $window_size $channels > out.smp
```

* `$path` - path to a WAV file
* `$window_size` - size of window (1024 by default)
* `$channels` - amount of channels to use (8 by default)

### Playing converted files
A kind person (@kebufu) has provided us with an fft audio player in Python which
means you can enjoy the hilariously high-quality audio without even having to
launch the game!

See

```
python3 ./ffplayer.py
```

for the usage help.
Besides Python 3 (obviously), it seems to need `pyaudio` installed —
so make sure it is.

### Requirements
* Audio file: must be mono.
* The OpenComputers program itself requires Lua 5.3, the sound card, and quite
  a lot of RAM.

import numpy as np
from os import path
from math import floor
from struct import unpack
from pyaudio import PyAudio
from sys import argv, stdout, stderr, exit

if len(argv) == 1:
    print(f"{argv[0]} <file> [-o outfile]", file=stderr)
    exit(-1)

f = open(argv[1], "rb")


def sin_wave(A, f, fs, phi, t):
    """
    :params A: amplitude
    :params f: wave frequency
    :params fs: sample rate
    :params phi: phase
    :params t: time
    """
    # An example for illustratory purposes:
    # If we let the time t = 1 s and the sample rate fs = 1000 Hz,
    # we obtain that the sampling interval equals Ts = 1 / fs = 0.001 s.
    # Therefore, the number of sample points is n = t / Ts = 1000;
    # that is, t seconds of sine wave is represented with n = t / Ts samples,
    # taken every Ts seconds.
    Ts = 1 / fs
    n = t / Ts
    n = np.arange(n)
    y = A * np.sin(2 * np.pi * f * n * Ts + phi * (np.pi / 180))
    return y


rate, windowSize, step, channels = unpack(">dddd", f.read(32))
fileSize = path.getsize(argv[1]) - 32
length = (fileSize) / rate / channels / 8 / 2 * windowSize
fileSize = floor(min(fileSize, length * rate * channels * 8 * 2 / windowSize))

delay = step / rate
chans = [unpack(">d", f.read(8))[0] for i in range(0, fileSize, 8)]
buffer = np.array([])
maxAmplitude = np.max(chans[1::2])
f.close()

print(f"length: {fileSize}B/{length}s.")

p = PyAudio()
stream = p.open(
    format=p.get_format_from_width(2),
    channels=1,
    rate=int(rate),
    output=True,
    frames_per_buffer=int(step),
)

try:
    out = argv.index("-o")
    import wave

    out = wave.open(argv[out + 1], "wb")
    out.setnchannels(1)
    out.setsampwidth(2)
    out.setframerate(rate)
except:
    out = None

for sample in range(0, len(chans), int(channels) * 2):
    buf = sin_wave(
        chans[sample + 1] / maxAmplitude / channels, chans[sample], rate, 0, delay
    )

    for i in range(2, int(channels) * 2, 2):
        buf += sin_wave(
            chans[sample + 1 + i] / maxAmplitude / channels,
            chans[sample + i],
            rate,
            0,
            delay,
        )

    data = (buf * 32767).astype(np.int16).tobytes()
    stream.write(data)

    if out:
        out.writeframes(data)

    stdout.write(
        "\rPlaying: %0.2f/%0.2fs" % ((sample / channels / 2 + 1) * delay, length)
    )

stream.close()

if out:
    out.close()

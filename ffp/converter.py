#!/usr/bin/env python3

import os
import struct
import sys

import numpy as np
import scipy.io.wavfile as wav

stdout = os.fdopen(sys.stdout.fileno(), "wb")

if len(sys.argv) == 1 or not sys.argv[1]:
    sys.stderr.write("Usage: %s <path> [window size] [channels]\n" % sys.argv[0])
    sys.exit(1)

window_size = 1024
channels = 8

if len(sys.argv) >= 3:
    window_size = int(sys.argv[2])
if len(sys.argv) >= 4:
    channels = int(sys.argv[3])

sample_rate, data = wav.read(sys.argv[1])

if type(data[0]) == np.ndarray:
    sys.stderr.write("Mono audio required\n")
    sys.exit(1)

stdout.write(struct.pack('>ddd', sample_rate, window_size, window_size))

for i in range(0, len(data), window_size):
    window = data[i:i+window_size]
    n = len(window)
    freq = np.fft.fftfreq(n, 1/sample_rate)[range(int(n / 2))]
    fourier = np.fft.fft(window) / n
    fourier = fourier[range(int(n / 2))]
    values = [x for x in sorted(zip(freq, np.abs(fourier)),
                                key=lambda x: x[1],
                                reverse=True)]
    for ch in range(channels):
        stdout.write(struct.pack('>dd', values[ch][0], values[ch][1]))

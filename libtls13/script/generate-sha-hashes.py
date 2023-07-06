#!/usr/bin/env python3

import hashlib
import random
import sys

match sys.argv[1] if len(sys.argv) >= 2 else None:
    case "sha256":
        algo = hashlib.sha256

    case "sha384":
        algo = hashlib.sha384

    case "sha512":
        algo = hashlib.sha512

    case _:
        print("Usage: ./script/generate-sha-hashes.py {sha256|sha384|sha512}")
        sys.exit(1)

sizes = list(range(1, 256)) + [256, 512, 1024, 2048, 4096, 8192]

for size in sizes:
    data = random.randbytes(size)
    print(data.hex(), algo(data).hexdigest())

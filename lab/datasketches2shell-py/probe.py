#!/usr/bin/env python3
"""Call the shipped datasketches-python 5.2.0 hll_sketch.deserialize(bytes)
binding on a genuine seed image with only wire byte 6 and the payload changed.
argv: module count value(hex) seed_path. Never opens a socket."""
import sys

module_name, count_s, value_s, seed_path = sys.argv[1:5]
sys.path.insert(0, sys.argv[0].rsplit("/", 1)[0])
module = __import__(module_name)

seed = open(seed_path, "rb").read()
count = int(count_s)
value = int(value_s, 0)
need = 8 + count * 4
buf = bytearray([value]) * need
buf[:min(len(seed), need)] = seed[:need]
buf[6] = count
print("PY_ENV count=%d image_bytes=%d value=%#x" % (count, len(buf), value), flush=True)
sketch = module.hll_sketch.deserialize(bytes(buf))
print("PY_ESTIMATE %.17g" % sketch.get_estimate(), flush=True)

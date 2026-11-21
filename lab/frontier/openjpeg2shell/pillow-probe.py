#!/usr/bin/env python3
"""Open and fully decode one JPEG 2000 codestream through Pillow.

Local process only. PILROOT selects an installed Pillow tree (the official
wheel or the locally built one); the caller controls LD_LIBRARY_PATH and
LD_PRELOAD for the libopenjp2 variant under test.
"""
import os
import sys

root = os.environ.get("PILROOT")
if root:
    sys.path.insert(0, root)

from PIL import Image, features

print("PIL_JPG2000 %s" % features.version("jpg_2000"), flush=True)
path = sys.argv[1]
im = Image.open(path)
print("OPENED format=%s size=%s mode=%s" % (im.format, im.size, im.mode), flush=True)
try:
    im.load()
    print("LOAD_OK", flush=True)
except Exception as exc:
    print("LOAD_EXC %s %s" % (type(exc).__name__, exc), flush=True)

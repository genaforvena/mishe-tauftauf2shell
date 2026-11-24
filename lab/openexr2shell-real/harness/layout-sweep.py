#!/usr/bin/env python3
"""W189: build symlinked paths of exact argv length for one PoC file.

The OpenEXRCore context stores the filename in a heap string
(context.c:169 exr_attr_string_create), so argv path length is an external
heap-layout knob. Every path below resolves to the same file bytes.
"""
import os
import sys

root, target, out = sys.argv[1:4]
prefix = root + "/"
lengths = [24, 32, 64, 96, 128, 160, 200, 248, 300, 512, 1024, 2048, 3072, 3900]
os.makedirs(root, exist_ok=True)
target = os.path.abspath(target)
paths = []
for total in lengths:
    body = total - len(prefix)
    if body < 1:
        raise SystemExit("path too short: %d" % total)
    parts = []
    while body > 255:
        parts.append("d" * 255)
        body -= 256
    parts.append("f" + "a" * (body - 1))
    path = prefix + "/".join(parts)
    if len(path) != total:
        raise SystemExit("bad length %d: %d" % (total, len(path)))
    dirname = os.path.dirname(path)
    os.makedirs(dirname, exist_ok=True)
    if os.path.lexists(path):
        os.unlink(path)
    os.symlink(target, path)
    paths.append(path)
with open(out, "w") as f:
    for p in paths:
        f.write("%d %s\n" % (len(p), p))

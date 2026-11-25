#!/usr/bin/env python3
"""Insert a minimal custom-type (OPAQUE) attribute into an EXR header.

The inserted attribute has no application-registered handler, so OpenEXRCore
parses it as EXR_ATTR_OPAQUE with NULL unpack/pack/destroy pointers.
"""

import struct
import sys

src, dst = sys.argv[1], sys.argv[2]
data = bytearray(open(src, "rb").read())
assert data[:4] == b"v/1\x01", "not an EXR file"

# Walk attributes from offset 8; an empty name terminates the header.
pos = 8
while True:
    end = data.index(b"\0", pos)
    name = bytes(data[pos:end])
    if not name:
        break
    pos = end + 1
    tend = data.index(b"\0", pos)
    pos = tend + 1
    size = struct.unpack_from("<i", data, pos)[0]
    assert size >= 0
    pos += 4 + size

attr = b"w208custom\0w208type\0" + struct.pack("<i", 4) + b"W208"
out = bytes(data[:pos]) + attr + bytes(data[pos:])
open(dst, "wb").write(out)
print(f"inserted opaque attribute at header offset {pos}; size {len(out)}")

